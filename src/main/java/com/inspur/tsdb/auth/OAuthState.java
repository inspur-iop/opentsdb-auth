package com.inspur.tsdb.auth;

import org.jboss.netty.channel.Channel;

/**
 *
 * Created by yuanxiaolong on 2018/1/19.
 */
public class OAuthState implements net.opentsdb.auth.AuthState {

    private Channel channel;

    private AuthStatus status;

    private String message;

    private byte[] token;

    private String user;

    public OAuthState(String message, String user, byte[] token,
                      AuthStatus status) {
        this.message = message;
        this.user = user;
        this.token = token;
        this.status = status;
    }

    public String getUser() {
        return user;
    }

    public AuthStatus getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }

    public Throwable getException() {
        return null;
    }

    public void setChannel(Channel channel) {
        this.channel = channel;
    }

    public byte[] getToken() {

        return token;
    }
}
