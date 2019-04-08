package com.inspur.tsdb.auth;

import com.google.common.base.Strings;
import com.stumbleupon.async.Deferred;
import net.opentsdb.auth.AuthState;
import net.opentsdb.auth.Authentication;
import net.opentsdb.auth.Authorization;
import net.opentsdb.core.TSDB;
import net.opentsdb.stats.StatsCollector;
import net.opentsdb.tsd.HttpRpcPluginQuery;
import net.opentsdb.utils.Config;

import java.util.Map;

import org.jboss.netty.channel.Channel;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * 认证
 * Created by yuanxiaolong on 2018/1/19.
 */
public final class HBaseAuthentication extends Authentication {

    private static final Logger log = LoggerFactory.getLogger(Authentication.class);

    private Authorization authorization;

    //
    private TSDB tsdb;

    //配置
    private Config config;

    public void initialize(final TSDB tsdb) {
        log.debug("--------------Authentication initialize------------");
        config = tsdb.getConfig();
        this.tsdb = tsdb;

        authorization = authorization();
    }

    public Deferred<Object> shutdown() {
        log.debug("--------------Authentication shutdown------------");
        return null == authorization?Deferred.<Object>fromResult(true) :
                authorization.shutdown();
    }

    public String version() {
        return authorization.version();
    }

    public void collectStats(StatsCollector statsCollector) {
        log.debug("--------------Authentication collectStats------------");
    }

    public AuthState authenticateTelnet(Channel channel, String[] strings) {
        log.debug("--------------Authentication authenticateTelnet------------");
        return new OAuthState(null, null, null, AuthState.AuthStatus.FORBIDDEN);
    }

    //认证
    public AuthState authenticateHTTP(Channel channel, HttpRequest httpRequest) {
        log.debug("--------------Authentication authenticateHTTP:{}------------", httpRequest.getUri());
        AuthState state = null;
        String token = null;
        if (httpRequest.getUri().startsWith("/api")) {
            if (httpRequest.getUri().startsWith("/api/auth")
                    || httpRequest.getUri().startsWith("/api/config")
                    || httpRequest.getUri().startsWith("/api/version")
                    || httpRequest.getUri().startsWith("/api/serializers")) {
                state = new OAuthState(null, null, null, AuthState.AuthStatus.SUCCESS);
            } else {//api/user api/*
                HttpRpcPluginQuery query = new HttpRpcPluginQuery(tsdb, httpRequest, channel);
//                if (!Strings.isNullOrEmpty(query.getQueryStringParam("token"))) {
//                    token = query.getQueryStringParam("token");
//                    state = new OAuthState(null, null, token.getBytes(), AuthState.AuthStatus.UNAUTHORIZED);
//                    state = authorization.allowHttpApi(state, httpRequest);
//                } else {
//                    state = new OAuthState(null, null, null, AuthState.AuthStatus.FORBIDDEN);
//                }
                
                if (httpRequest.getHeader("Authorization") != null) {
                    token = httpRequest.getHeader("Authorization");
                    log.info("-------------------get token {}-------------------",token);
                    if (token.startsWith("bearer")) {
                    	token = token.substring(7);
                        state = new OAuthState(null, null, token.getBytes(), AuthState.AuthStatus.UNAUTHORIZED);
                        state = authorization.allowHttpApi(state, httpRequest);
                    } else {
                    	state = new OAuthState(null, null, null, AuthState.AuthStatus.FORBIDDEN);
                    }
                } else {
                    state = new OAuthState(null, null, null, AuthState.AuthStatus.FORBIDDEN);
                }
            }
        }else{
            state = new OAuthState(null, null, null, AuthState.AuthStatus.SUCCESS);
        }
        state.setChannel(channel);

        return state;
    }

    //鉴权
    public Authorization authorization() {
        log.debug("--------------Authentication authorization------------");
        Authorization authorization = new HBaseAuthorization();
        authorization.initialize(tsdb);
        return authorization;
    }
}
