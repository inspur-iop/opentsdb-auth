package com.inspur.tsdb.auth;

import com.google.common.base.Strings;
import com.stumbleupon.async.Callback;
import com.stumbleupon.async.Deferred;
import net.opentsdb.auth.*;
import net.opentsdb.auth.AuthState;
import net.opentsdb.core.TSDB;
import net.opentsdb.core.TSQuery;
import net.opentsdb.query.pojo.Query;
import net.opentsdb.stats.StatsCollector;
import net.opentsdb.utils.Config;
import net.opentsdb.utils.TokenCache;
import org.hbase.async.*;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.json.JSONArray;
import org.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * 鉴权
 * Created by yuanxiaolong on 2018/1/19.
 */
public class HBaseAuthorization extends Authorization {

    private static final Logger LOG = LoggerFactory.getLogger(Authorization.class);

    private static final String COLUMN_FAMILY = "u";
    private static final String ROLE_QUALFIER = "roles";
    private static final String TOKEN_QUALIFIER = "token";
    private static final Long _1_HOUR = 3600000L;

    //用户表名称
    private String userTableName;

    //角色与Uri映射关系
    private Map<String, Set<String>> roleUris;

    private TSDB tsdb;

    //配置
    private Config config;

    /** Client for the HBase cluster to use.  */
    private HBaseClient client;

    public void initialize(final TSDB tsdb) {
        LOG.debug("--------------Authorization initialize------------");
        this.tsdb = tsdb;
        config = tsdb.getConfig();
        userTableName = config.getString("tsd.core.user.table");
        if(Strings.isNullOrEmpty(userTableName)){
            userTableName = "tsdb-user";
        }

        String rUs = config.getString("tsd.core.role.permissions.info");
        if(Strings.isNullOrEmpty(rUs)){
            throw new IllegalArgumentException("Missing config "
                    + "'tsd.core.role.permissions.info'");
        }

        //加载role-Uris映射关系
        loadRoleUris(rUs);

        //获取HBaseClient实例对象
        client = tsdb.getClient();
    }

    /**
     * 加载role-Uris映射关系
     * @param rUs
     */
    private void loadRoleUris(String rUs){
        LOG.debug("--------------Authorization loadRoleUris------------");
        try {
            JSONArray array = new JSONArray(rUs);
            roleUris = new HashMap<String, Set<String>>();
            for (int i = 0; i < array.length(); i++) {
                String role = array.getJSONObject(i).getString("role");
                JSONArray uris = array.getJSONObject(i).getJSONArray("uris");
                if(uris != null && uris.length() > 0){
                    Set<String> uriSet = new HashSet<String>(uris.length());
                    for (int j = 0; j < uris.length(); j++){
                        uriSet.add(uris.getString(j));
                    }
                    roleUris.put(role, uriSet);
                }
            }
        }catch (JSONException e){
            throw new IllegalArgumentException("role and uri format error ");
        }
    }

    public Deferred<Object> shutdown() {
        LOG.debug("--------------Authorization shutdown------------");
        return Deferred.<Object>fromResult(true);
    }

    public String version() {
        return "1.0.0";
    }

    public void collectStats(StatsCollector collector) {
        LOG.debug("--------------Authorization collectStats------------");
    }

    @Override
    public AuthState allowHttpApi(AuthState state, HttpRequest httpRequest) {
        String token = new String(state.getToken());
        String rowKey = TokenCache.getRowKey(token);
        LOG.debug("--------------Authorization allowHttpApi(httpRequest), token:{}------------", new String(state.getToken()));
        if(Strings.isNullOrEmpty(rowKey)){
            try {
                rowKey = scanHBaseRowKey(token);
            } catch (Exception e){
                LOG.error("Scan HBase user table to acquire token error :{} ", e);
                return state;
            }
        }
        LOG.debug("--------------Authorization allowHttpApi(httpRequest), rowKey:{}------------", rowKey);
        String user = null;
        if(!Strings.isNullOrEmpty(rowKey)
                && validateRoleUris(rowKey, httpRequest.getUri())){
            if(rowKey.contains("|")){
                String[] spliters = rowKey.split("|");
                if(spliters.length > 0){
                    user = spliters[0];
                }
            }else
                user = rowKey;

            return new OAuthState(state.getMessage(), user, state.getToken(), AuthState.AuthStatus.SUCCESS);
        }

        return state;
    }

    private String scanHBaseRowKey(String token) throws Exception{
        final org.hbase.async.Scanner scanner = client.newScanner(userTableName);
        scanner.setFamily(COLUMN_FAMILY);
        scanner.setQualifier(TOKEN_QUALIFIER);
        scanner.setMinTimestamp(System.currentTimeMillis());
        ValueFilter tokenFilter = new ValueFilter(CompareFilter.CompareOp.EQUAL, new BinaryComparator(token.getBytes()));
        scanner.setFilter(tokenFilter);
        ArrayList<ArrayList<KeyValue>> rows = null;

        //线程阻塞直到返回所有查询结果
        while ((rows = scanner.nextRows(1).joinUninterruptibly()) != null){
            for (ArrayList<KeyValue> row : rows) {
                KeyValue kv = row.get(0);
                LOG.debug("{}, {}, {}, {}", new String(kv.key()), new String(kv.value()), kv.timestamp(), kv.timestamp() - System.currentTimeMillis());
                if(kv.timestamp() >= System.currentTimeMillis()){
                    String rowKey = new String(kv.key());
                    TokenCache.put2TokenRowKey(token, rowKey, kv.timestamp());
                    return new String(kv.key());
                }
            }
        }

        return null;
    }

    /**
     *
     * @param rowKey
     * @param uri
     * @return
     */
    private Boolean validateRoleUris(final String rowKey, final String uri){
        GetRequest request = new GetRequest(userTableName, rowKey, COLUMN_FAMILY, ROLE_QUALFIER);

        Deferred<String> deferred =  client.get(request)
                .addCallback(new Callback<String, ArrayList<KeyValue>>() {
                    @Override
                    public String call(ArrayList<KeyValue> list) throws Exception {
                        if(list.size() > 0){
                            return new String(list.get(0).value());
                        }
                        return null;
                    }
                });

        try {
            String roles = deferred.join();
            if(Strings.isNullOrEmpty(roles)) return false;
            int idx = uri.indexOf("?");
            String _uri = uri;
            if(idx > 0){
                _uri = uri.substring(0, idx);
            }
            StringTokenizer tokenizer = new StringTokenizer(roles, ",");
            while (tokenizer.hasMoreTokens()){
                String role = tokenizer.nextToken();
                Set<String> uris = this.roleUris.get(role);
                if(uris.contains(_uri)) return true;
            }
        }catch (Exception e){
            LOG.error("validateRoleUris exception:{}", e);
        }

        return false;
    }

    public AuthState allowQuery(AuthState state, TSQuery query) {
        LOG.debug("--------------Authorization allowQuery(TSQuery)------------");
        return state;
    }

    public AuthState allowQuery(AuthState state, Query query) {
        LOG.debug("--------------Authorization allowQuery(Query)------------");
        return state;
    }
}
