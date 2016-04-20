/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.clef;

class ClefAuthenticatorConstants {
    public static final String AUTHENTICATOR_NAME = "ClefAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "clef";
    public static final String CLEF_OAUTH_ENDPOINT = "https://localhost:9443/clefauthenticationendpoint/ClefEndPoint.jsp";
    public static final String CLEF_TOKEN_ENDPOINT = "https://clef.io/api/v1/authorize";
    public static final String CLEF_USERINFO_ENDPOINT = "https://clef.io/api/v1/info";
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    public static final String CLIENT_ID = "Client ID";
    public static final String CALLBACK_URL = "Callback URL";
    public static final String CLIENT_SECRET = "Client Secret";
    public static final String CODE = "code";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String ID = "id";
    public static final String LAST_NAME = "last_name";
    public static final String USER_INFO = "info";
    public static final String CLEF_ID = "http://wso2.org/claims/clefId";
    public static final String REQUEST_TYPE = "Request_type";
    public static final String LOGIN = "login";
    public static final String CONNECT = "connect";
    public static final String DEFAULT = "Default";
}