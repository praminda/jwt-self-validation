/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.apimgt.sample;

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.ApplicationConstants;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.AMDefaultKeyManagerImpl;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.keymgt.client.SubscriberKeyMgtClient;
import org.wso2.carbon.apimgt.keymgt.client.SubscriberKeyMgtClientPool;

import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class ExternalKeyManager extends AMDefaultKeyManagerImpl {

    private static final Log log = LogFactory.getLog(ExternalKeyManager.class);

    // Mock oauth app information holder
    private Map<String, OAuthApplicationInfo> oauthApps;

    public ExternalKeyManager() {
        oauthApps = new HashMap<>();
    }

    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

        // OAuthApplications are created by calling to APIKeyMgtSubscriber Service
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();

        // Subscriber's name should be passed as a parameter, since it's under the subscriber the OAuth App is created.
        String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.
                OAUTH_CLIENT_USERNAME);
        String applicationName = oAuthApplicationInfo.getClientName();
        String keyType = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.APP_KEY_TYPE);
        String callBackURL = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.APP_CALLBACK_URL);
        if (keyType != null) {
            applicationName = applicationName + '_' + keyType;
        }

        if (log.isDebugEnabled()) {
            log.debug("Trying to create OAuth application :" + applicationName);
        }

        String tokenScope = (String) oAuthApplicationInfo.getParameter("tokenScope");
        String[] tokenScopes = new String[1];
        tokenScopes[0] = tokenScope;

        org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo info = null;

        try {
            org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo applicationToCreate =
                    new org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo();
            applicationToCreate.setIsSaasApplication(oAuthApplicationInfo.getIsSaasApplication());
            applicationToCreate.setCallBackURL(callBackURL);
            applicationToCreate.setClientName(applicationName);
            applicationToCreate.setAppOwner(userId);
            applicationToCreate.setJsonString(oAuthApplicationInfo.getJsonString());
            info = createOAuthApplication(applicationToCreate);
        } catch (Exception e) {
            handleException("Can not create OAuth application  : " + applicationName, e);
        }

        if (info == null || info.getJsonString() == null) {
            handleException("OAuth app does not contains required data  : " + applicationName,
                    new APIManagementException("OAuth app does not contains required data"));
        }

        oAuthApplicationInfo.addParameter("tokenScope", tokenScopes);
        oAuthApplicationInfo.setClientName(info.getClientName());
        oAuthApplicationInfo.setClientId(info.getClientId());
        oAuthApplicationInfo.setCallBackURL(info.getCallBackURL());
        oAuthApplicationInfo.setClientSecret(info.getClientSecret());
        oAuthApplicationInfo.setIsSaasApplication(info.getIsSaasApplication());

        try {
            JSONObject jsonObject = new JSONObject(info.getJsonString());

            if (jsonObject.has(ApplicationConstants.
                    OAUTH_REDIRECT_URIS)) {
                oAuthApplicationInfo.addParameter(ApplicationConstants.
                        OAUTH_REDIRECT_URIS, jsonObject.get(ApplicationConstants.OAUTH_REDIRECT_URIS));
            }

            if (jsonObject.has(ApplicationConstants.OAUTH_CLIENT_NAME)) {
                oAuthApplicationInfo.addParameter(ApplicationConstants.
                        OAUTH_CLIENT_NAME, jsonObject.get(ApplicationConstants.OAUTH_CLIENT_NAME));
            }

            if (jsonObject.has(ApplicationConstants.OAUTH_CLIENT_GRANT)) {
                oAuthApplicationInfo.addParameter(ApplicationConstants.
                        OAUTH_CLIENT_GRANT, jsonObject.get(ApplicationConstants.OAUTH_CLIENT_GRANT));
            }
        } catch (JSONException e) {
            handleException("Can not retrieve information of the created OAuth application", e);
        }

        return oAuthApplicationInfo;

    }

    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();

        try {

            String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_USERNAME);
            String[] grantTypes = null;
            if (oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_GRANT) != null) {
                grantTypes = ((String)oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_GRANT))
                        .split(",");
            }
            String applicationName = oAuthApplicationInfo.getClientName();
            String keyType = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.APP_KEY_TYPE);

            if (keyType != null) {
                applicationName = applicationName + "_" + keyType;
            }
            log.debug("Updating OAuth Client with ID : " + oAuthApplicationInfo.getClientId());

            if (log.isDebugEnabled() && oAuthApplicationInfo.getCallBackURL() != null) {
                log.debug("CallBackURL : " + oAuthApplicationInfo.getCallBackURL());
            }

            if (log.isDebugEnabled() && applicationName != null) {
                log.debug("Client Name : " + applicationName);
            }
            org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo applicationInfo = updateOAuthApplication(userId,
                    applicationName, oAuthApplicationInfo.getCallBackURL(),oAuthApplicationInfo.getClientId(),
                    grantTypes);
            OAuthApplicationInfo newAppInfo = new OAuthApplicationInfo();
            newAppInfo.setClientId(applicationInfo.getClientId());
            newAppInfo.setCallBackURL(applicationInfo.getCallBackURL());
            newAppInfo.setClientSecret(applicationInfo.getClientSecret());
            newAppInfo.setJsonString(applicationInfo.getJsonString());

            return newAppInfo;
        } catch (Exception e) {
            handleException("Error occurred while updating OAuth Client : ", e);
        }
        return null;
    }

    public void deleteApplication(String consumerKey) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Trying to delete OAuth application for consumer key :" + consumerKey);
        }

        // TODO: 8/17/18 Send delete oauth application request to actual KM
        oauthApps.remove(consumerKey);
    }

    public OAuthApplicationInfo retrieveApplication(String consumerKey) throws APIManagementException {

        if (log.isDebugEnabled()) {
            log.debug("Trying to retrieve OAuth application for consumer key :" + consumerKey);
        }

        OAuthApplicationInfo oAuthApplicationInfo = new OAuthApplicationInfo();
        try {
            OAuthApplicationInfo info = getOAuthApplication(consumerKey);

            if (info == null || info.getClientId() == null) {
                return null;
            }
            oAuthApplicationInfo.setClientName(info.getClientName());
            oAuthApplicationInfo.setClientId(info.getClientId());
            oAuthApplicationInfo.setCallBackURL(info.getCallBackURL());
            oAuthApplicationInfo.setClientSecret(info.getClientSecret());

            JSONObject jsonObject = new JSONObject(info.getJsonString());

            if (jsonObject.has(ApplicationConstants.
                    OAUTH_REDIRECT_URIS)) {
                oAuthApplicationInfo.addParameter(ApplicationConstants.
                        OAUTH_REDIRECT_URIS, jsonObject.get(ApplicationConstants.OAUTH_REDIRECT_URIS));
            }

            if (jsonObject.has(ApplicationConstants.OAUTH_CLIENT_NAME)) {
                oAuthApplicationInfo.addParameter(ApplicationConstants.
                        OAUTH_CLIENT_NAME, jsonObject.get(ApplicationConstants.OAUTH_CLIENT_NAME));
            }

            if (jsonObject.has(ApplicationConstants.OAUTH_CLIENT_GRANT)) {
                oAuthApplicationInfo.addParameter(ApplicationConstants.
                        OAUTH_CLIENT_GRANT, jsonObject.get(ApplicationConstants.OAUTH_CLIENT_GRANT));
            }

        } catch (Exception e) {
            handleException("Can not retrieve OAuth application for the given consumer key : " + consumerKey, e);
        }
        return oAuthApplicationInfo;
    }

    public AccessTokenInfo getTokenMetaData(String token) throws APIManagementException {
        AccessTokenInfo tokenInfo = new AccessTokenInfo();

        try {
            SignedJWT signedJWT = getSignedJWT(token);
            ReadOnlyJWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            tokenInfo.setEndUserName(claimsSet.getSubject());
            // TODO: 8/15/18 Set consumer Key
//            tokenInfo.setConsumerKey(clientApplicationDTO.getConsumerKey());
            tokenInfo.setValidityPeriod(claimsSet.getExpirationTime().getTime());
            tokenInfo.setIssuedTime(claimsSet.getIssueTime().getTime());
            Object scopeObj = claimsSet.getAllClaims().get("scope");
            String[] scopes = null;

            if (scopeObj instanceof String) {
                scopes = ((String) scopeObj).split(" ");
                tokenInfo.setScope(scopes);
            }

            String applicationTokenScope = ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService().
                    getAPIManagerConfiguration().getFirstProperty(APIConstants.APPLICATION_TOKEN_SCOPE);

            if (scopes != null && applicationTokenScope != null && !applicationTokenScope.isEmpty()) {
                if (Arrays.asList(scopes).contains(applicationTokenScope)) {
                    tokenInfo.setApplicationToken(true);
                }
            }

        } catch (ParseException e) {
            throw new APIManagementException("Error while retrieving token information.", e);
        }

        return tokenInfo;
    }

    private org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo createOAuthApplication (
            org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo applicationToCreate) throws Exception {
        org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo info =
                new org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo();

        // TODO: 8/17/18 Send oauth app creation request to actual KM

        // Create a dummy mock clientId:clientSecrete pair
        info.setClientId(UUID.randomUUID().toString());
        info.setClientSecret(UUID.randomUUID().toString());

        return info;
    }

    private org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo updateOAuthApplication(String userId,
            String applicationName, String callBackURL, String clientId, String[] grantTypes) throws Exception {
        SubscriberKeyMgtClient keyMgtClient = null;
        try {
            keyMgtClient = SubscriberKeyMgtClientPool.getInstance().get();
            return keyMgtClient
                    .updateOAuthApplication(userId, applicationName, callBackURL, clientId, grantTypes);
        } finally {
            SubscriberKeyMgtClientPool.getInstance().release(keyMgtClient);
        }

    }

    private OAuthApplicationInfo getOAuthApplication(String consumerKey)
            throws Exception {
        // TODO: 8/17/18 Send get oauth application request to actual KM
        return oauthApps.get(consumerKey);
    }

    private SignedJWT getSignedJWT(String accessToken) throws ParseException {
        return SignedJWT.parse(accessToken);
    }

    /**
     * common method to log and throw exceptions.
     *
     * @param msg error message for the exception to be thrown
     * @param e   captured exception
     * @throws org.wso2.carbon.apimgt.api.APIManagementException
     */
    private void handleException(String msg, Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }
}
