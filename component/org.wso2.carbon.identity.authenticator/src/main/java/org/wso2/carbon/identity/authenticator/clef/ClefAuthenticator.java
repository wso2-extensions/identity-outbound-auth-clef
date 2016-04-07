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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of clef.
 */
public class ClefAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(ClefAuthenticator.class);

    /**
     * check and process the httpServletRequest to process.
     *
     * @param httpServletRequest http request
     * @return weather true or false
     */
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter(ClefAuthenticatorConstants.CODE) != null;
    }

    /**
     * Identify the context.
     *
     * @param httpServletRequest http request
     * @return context identifier
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter(ClefAuthenticatorConstants.SESSION_DATA_KEY);
    }

    /**
     * Get clef token endpoint.
     */
    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        return ClefAuthenticatorConstants.CLEF_TOKEN_ENDPOINT;
    }

    /**
     * Get clef user info endpoint.
     */
    @Override
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {
        return ClefAuthenticatorConstants.CLEF_USERINFO_ENDPOINT;
    }

    /**
     * Check ID token in clef OAuth.
     */
    @Override
    protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {
        return false;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return ClefAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return ClefAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Get Configuration Properties
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<>();
        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName(ClefAuthenticatorConstants.CLIENT_ID);
        clientId.setRequired(true);
        clientId.setDescription("Enter Clef client identifier value");
        clientId.setDisplayOrder(0);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName(ClefAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter Clef client secret value");
        clientSecret.setDisplayOrder(1);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName(ClefAuthenticatorConstants.CALLBACK_URL);
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDescription("Enter the callback url");
        callbackUrl.setDisplayOrder(2);
        configProperties.add(callbackUrl);
        return configProperties;
    }

    /**
     * This is override because of some values are hard coded and input
     * values validations are not required.
     *
     * @param httpServletRequest    http request
     * @param httpServletResponse   http response
     * @param authenticationContext authentication context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        AuthenticatedUser authenticatedUser = getUsername(authenticationContext);
        String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        String clefUserId;
        String requestType;
        try {
            UserStoreManager userStoreManager = getUserStoreManager(authenticationContext);
            clefUserId = userStoreManager.getUserClaimValue(username, ClefAuthenticatorConstants.CLEF_ID, null);
            if (StringUtils.isEmpty(clefUserId)) {
                requestType = ClefAuthenticatorConstants.LOGIN;
            } else {
                requestType = ClefAuthenticatorConstants.CONNECT;
            }
            String clefLoginPage = ClefAuthenticatorConstants.CLEF_OAUTH_ENDPOINT;
            Map<String, String> authenticatorProperties = authenticationContext.getAuthenticatorProperties();
            String callbackurl = getCallbackUrl(authenticatorProperties);
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(authenticationContext
                    .getQueryParams(), authenticationContext.getCallerSessionKey(), authenticationContext
                    .getContextIdentifier());
            httpServletResponse.sendRedirect(httpServletResponse.encodeRedirectURL(clefLoginPage + ("?" + queryParams
                    + "&" + OIDCAuthenticatorConstants.CLIENT_ID + "=" + authenticationContext
                    .getAuthenticatorProperties().get(OIDCAuthenticatorConstants.CLIENT_ID)) + "&"
                    + ClefAuthenticatorConstants.REQUEST_TYPE + "=" + requestType + "&"
                    + IdentityApplicationConstants.OAuth2.CALLBACK_URL + "=" + callbackurl));
            if (log.isDebugEnabled()) {
                log.debug("Request send to " + clefLoginPage);
            }
            authenticationContext.setCurrentAuthenticator(getName());
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user claim - "
                    + ClefAuthenticatorConstants.CLEF_ID, e);
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    /**
     * This is override because of we are working with claims.
     *
     * @param httpServletRequest    http request
     * @param httpServletResponse   http response
     * @param authenticationContext authentication context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        Map<String, String> authenticatorProperties = authenticationContext.getAuthenticatorProperties();
        String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
        String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
        String tokenEndPoint = getTokenEndpoint(authenticatorProperties);
        String callbackurl = getCallbackUrl(authenticatorProperties);
        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        OAuthClientResponse oAuthResponse;
        AuthenticatedUser authenticatedUser = getUsername(authenticationContext);
        String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        String clefUserId;
        String accessToken;
        try {
            OAuthAuthzResponse authResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(httpServletRequest);
            String code = authResponse.getCode();
            if (log.isDebugEnabled()) {
                log.debug("Code received from clef");
            }
            OAuthClientRequest accessRequest = OAuthClientRequest
                    .tokenLocation(tokenEndPoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(clientId)
                    .setClientSecret(clientSecret)
                    .setRedirectURI(callbackurl)
                    .setCode(code)
                    .buildBodyMessage();
            oAuthResponse = oAuthClient.accessToken(accessRequest);
            accessToken = oAuthResponse.getParam(ClefAuthenticatorConstants.ACCESS_TOKEN);
            if (log.isDebugEnabled()) {
                log.debug("Access token received");
            }
        } catch (OAuthSystemException e) {
            throw new AuthenticationFailedException("Exception while building request for request access token", e);
        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException("Exception while requesting code", e);
        }
        if (StringUtils.isNotEmpty(accessToken)) {
            Map<String, Object> userClaims = getUserClaims(oAuthResponse);
            if (userClaims != null && !userClaims.isEmpty()) {
                try {
                    UserStoreManager userStoreManager = getUserStoreManager(authenticationContext);
                    clefUserId = userStoreManager.getUserClaimValue(username, ClefAuthenticatorConstants.CLEF_ID, null);
                    if (StringUtils.isNotEmpty(clefUserId) && clefUserId.equals(String
                            .valueOf(userClaims.get(ClefAuthenticatorConstants.ID)))) {
                        allowUser(userClaims, authenticationContext);
                    } else if (StringUtils.isEmpty(clefUserId)) {
                        userStoreManager.setUserClaimValue(username, ClefAuthenticatorConstants.CLEF_ID, String.
                                        valueOf(userClaims.get(ClefAuthenticatorConstants.ID)),
                                ClefAuthenticatorConstants.DEFAULT);
                        allowUser(userClaims, authenticationContext);
                    }
                } catch (UserStoreException e) {
                    throw new AuthenticationFailedException("Error occurred while loading user claim - ClefId", e);
                }
            } else {
                throw new AuthenticationFailedException("Selected user profile not found");
            }
        } else {
            throw new AuthenticationFailedException("Authentication Failed");
        }
    }

    /**
     * Allow user to login and set claims.
     *
     * @param userClaims            user claims
     * @param authenticationContext authentication context
     */
    private void allowUser(Map<String, Object> userClaims, AuthenticationContext authenticationContext) {
        AuthenticatedUser authenticatedUserObj;
        Map<ClaimMapping, String> claims;
        authenticatedUserObj = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(String
                .valueOf(userClaims.get(ClefAuthenticatorConstants.ID)));
        authenticatedUserObj.setAuthenticatedSubjectIdentifier(String
                .valueOf(userClaims.get(ClefAuthenticatorConstants.LAST_NAME)));
        claims = getSubjectAttributes(userClaims);
        authenticatedUserObj.setUserAttributes(claims);
        authenticationContext.setSubject(authenticatedUserObj);
    }

    /**
     * Get user information from user info endpoint.
     *
     * @param oAuthClientResponse oAuthResponse contain access token
     * @return user info
     */
    private Map<String, Object> getUserClaims(OAuthClientResponse oAuthClientResponse)
            throws AuthenticationFailedException {
        try {
            String json = sendRequest(ClefAuthenticatorConstants.CLEF_USERINFO_ENDPOINT,
                    oAuthClientResponse.getParam(ClefAuthenticatorConstants.ACCESS_TOKEN));
            if (log.isDebugEnabled()) {
                log.debug("User info received from  " + ClefAuthenticatorConstants.CLEF_USERINFO_ENDPOINT);
            }
            Map<String, Object> jsonObject = JSONUtils.parseJSON(json);
            Map<String, Object> jsonInfoObject = JSONUtils.parseJSON(String
                    .valueOf(jsonObject.get(ClefAuthenticatorConstants.USER_INFO)));
            return jsonInfoObject;
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while sent the request to get user info", e);
        }
    }

    /**
     * Get subject attributes.
     *
     * @param claimMap Map<String, Object>
     * @return attributes
     */
    private Map<ClaimMapping, String> getSubjectAttributes(Map<String, Object> claimMap) {
        Map<ClaimMapping, String> claims = new HashMap<>();
        if (claimMap != null) {
            for (Map.Entry<String, Object> entry : claimMap.entrySet()) {
                claims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null, false), entry.getValue().toString());
                if (log.isDebugEnabled()) {
                    log.debug("Adding claim from end-point data mapping : "
                            + entry.getKey() + " <> " + " : " + entry.getValue());
                }
            }
        }
        return claims;
    }

    /**
     * Get user store manager.
     *
     * @param authenticationContext authentication context
     * @return user store manager
     * @throws AuthenticationFailedException
     */
    private UserStoreManager getUserStoreManager(AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        AuthenticatedUser authenticatedUser = getUsername(authenticationContext);
        String tenantDomain;
        tenantDomain = authenticatedUser.getTenantDomain();
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm;
        UserStoreManager userStoreManager;
        try {
            userRealm = realmService.getTenantUserRealm(tenantId);
            userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new AuthenticationFailedException(
                    "Error occurred while loading user claim" + ClefAuthenticatorConstants.CLEF_ID, e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading userrealm or userstoremanager", e);
        }
        return userStoreManager;
    }

    /**
     * Get username
     *
     * @param authenticationContext authentication context
     * @return username
     */
    private AuthenticatedUser getUsername(AuthenticationContext authenticationContext) {
        AuthenticatedUser authenticatedUser = null;
        for (int i = 1; i <= authenticationContext.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = authenticationContext.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        return authenticatedUser;
    }
}