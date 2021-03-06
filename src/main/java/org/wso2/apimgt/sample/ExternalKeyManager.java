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
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.ApplicationConstants;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.AMDefaultKeyManagerImpl;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;

import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class ExternalKeyManager extends AMDefaultKeyManagerImpl {
    private static final Log log = LogFactory.getLog(ExternalKeyManager.class);

    // Mock consumer key
    private static final String CONSUMER_KEY = "4PFY8MmHtNtEqXuKcfXd6adEZqca";

    // Mock consumer key
    private static final String CONSUMER_SECRET = "pG6syBaBxgatCtapT9fAYC8EXFAa";

    // Mock access token, just to show in the store.
    private static final String ACCESS_TOKEN = "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlckBjYXJib24uc3VwZXIiLCJhdWQiOlsiNFBGWThNbUh0TnRFcVh1S2NmWGQ2YWRFWnFjYSJdLCJhenAiOiI0UEZZOE1tSHROdEVxWHVLY2ZYZDZhZEVacWNhIiwic2NvcGUiOiJ0c3QiLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDRcL29hdXRoMlwvdG9rZW4iLCJleHAiOjE1MzQ1MDQ1MjcsImlhdCI6MTUzNDUwMDkyNywianRpIjoiODQzNGIwZmEtM2E1NC00MjI3LWJlOTAtYmQ0Y2MzOWI0ZTY3In0.MyOLP-7-Fpbww7rsAZ2J6YkZa_pd4qEuOcNKlOF1N4hpTtbfzAothrmvq1dqnXmOI35rZUoaqOYaBZPF58fIzd1ixhjS0b2qo7fRlBD_iwK_FP8p1DgwXP1E3dTb4YFj3TeaN0XUFshNCV8M0S0l2obgdOU95qB81JkxUTEuRO9rw8wSVAaACe90oGBTVu9XNni7o6dVg07aE9Ic8n1n4fGjr1JJb9VQ9Y1GleO9XgFHqdMtOVEWgQHyanMbAaoBA8WguRKFd70-L9WoMOjbfQ57wVIqQgrll2YvV1jKLx74YOyu8N2M-z-uTut2ySD1EeKJC3IzrpdgFtTYvfJJ7A";

    // Mock oauth app information holder
    private Map<String, org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo> oauthApps;

    public ExternalKeyManager() {
        oauthApps = new HashMap<>();
    }

    @Override
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
            org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo applicationToCreate = new org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo();
            applicationToCreate.setIsSaasApplication(oAuthApplicationInfo.getIsSaasApplication());
            applicationToCreate.setCallBackURL(callBackURL);
            applicationToCreate.setClientName(applicationName);
            applicationToCreate.setAppOwner(userId);
            applicationToCreate.setJsonString(oAuthApplicationInfo.getJsonString());
            info = createOAuthAppInKM(applicationToCreate);
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

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();

        try {

            String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_USERNAME);
            String[] grantTypes = null;

            if (oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_GRANT) != null) {
                grantTypes = ((String) oAuthApplicationInfo.getParameter(ApplicationConstants.OAUTH_CLIENT_GRANT))
                        .split(",");
            }

            String applicationName = oAuthApplicationInfo.getClientName();
            String keyType = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.APP_KEY_TYPE);

            if (keyType != null) {
                applicationName = applicationName + "_" + keyType;
            }

            if (log.isDebugEnabled()) {
                log.debug("Updating OAuth Client with ID : " + oAuthApplicationInfo.getClientId());

                if (oAuthApplicationInfo.getCallBackURL() != null) {
                    log.debug("CallBackURL : " + oAuthApplicationInfo.getCallBackURL());
                }
                if (applicationName != null) {
                    log.debug("Client Name : " + applicationName);
                }
            }

            // Update oauth app in KM
            org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo applicationInfo = updateOAuthAppInKM(userId,
                    applicationName, oAuthApplicationInfo.getCallBackURL(), oAuthApplicationInfo.getClientId(),
                    grantTypes);

            // Map new application information to OAuthApplicationInfo
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

    @Override
    public void deleteApplication(String consumerKey) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Trying to delete OAuth application for consumer key :" + consumerKey);
        }

        // TODO: 8/17/18 Send delete oauth application request to actual KM
        oauthApps.remove(consumerKey);
    }

    @Override
    public OAuthApplicationInfo retrieveApplication(String consumerKey) throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Trying to retrieve OAuth application for consumer key :" + consumerKey);
        }

        OAuthApplicationInfo oAuthApplicationInfo = new OAuthApplicationInfo();
        try {
            // Retrieve Oauth application from Key Manager
            org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo info = getOAuthAppFromKM(consumerKey);

            if (info == null || info.getClientId() == null) {
                return null;
            }

            // Convert retrieved KM OauthApp data model to OAuthApplicationInfo
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

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest tokenRequest) throws APIManagementException {
        // TODO: 8/17/18 Implement token request to Actual KM

        // Mock token info
        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        tokenInfo.setAccessToken(ACCESS_TOKEN);
        tokenInfo.setValidityPeriod(System.currentTimeMillis());

        return tokenInfo;
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String token) throws APIManagementException {
        AccessTokenInfo tokenInfo = new AccessTokenInfo();

        try {
            SignedJWT signedJWT = getSignedJWT(token);
            ReadOnlyJWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            tokenInfo.setEndUserName(claimsSet.getSubject());
            tokenInfo.setConsumerKey(signedJWT.getJWTClaimsSet().getAudience().get(0));
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

    /**
     * Create an OAuth Application in Key Manager(KM). This function should be used only to implement
     * the logic of communication with KM.
     *
     * @param applicationToCreate populated data model of the application to be created
     * @return create application at the KM side
     */
    private org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo createOAuthAppInKM(
            org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo applicationToCreate) {
        org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo info = new org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo();
        // TODO: 8/17/18 Send oauth app creation request to actual KM

        // =====================================
        // Sample for talking with KM over http
        // =====================================

//        HttpClient client = new DefaultHttpClient();
//        String jsonPayload = // payload for KM
//        HttpPost httpPost = new HttpPost(registrationUrl);
//        httpPost.setEntity(new StringEntity(jsonPayload, "UTF8"));
//        httpPost.setHeader("CONTENT_TYPE", APPLICATION_JSON_CONTENT_TYPE);
//        httpPost.setHeader("AUTHORIZATION", "Bearer" + TOKEN);
//        HttpResponse response = client.execute(httpPost);

        // Set mock clientId:clientSecrete pair
        info.setClientId(CONSUMER_KEY);
        info.setClientSecret(CONSUMER_SECRET);
        info.setJsonString(applicationToCreate.getJsonString());
        info.setClientName(applicationToCreate.getClientName());
        info.setCallBackURL(applicationToCreate.getCallBackURL());
        info.setIsSaasApplication(applicationToCreate.getIsSaasApplication());
        oauthApps.put(CONSUMER_KEY, info);

        return info;
    }

    /**
     * Update the OAuth application details in Key Manager(KM). This function should be used only to implement
     * the logic of communication with KM.
     *
     * @param userId          updated {@link ApplicationConstants#OAUTH_CLIENT_USERNAME} parameter
     * @param applicationName updated client name for the application
     * @param callBackURL     updated callback url for the application
     * @param clientId        client id of an existing application to be updated
     * @param grantTypes      updated set of grant types for the application
     * @return updated oauth application
     */
    private org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo updateOAuthAppInKM(String userId,
            String applicationName, String callBackURL, String clientId, String[] grantTypes) {
        // TODO: 8/20/18 Send update oauth application request to actual KM

        // Update in-memory app details
        org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo newApp = oauthApps.get(clientId);
        newApp.setCallBackURL(callBackURL);
        newApp.setClientName(applicationName);

        return newApp;
    }

    /**
     * Retrieve OAuth application details from Key Manager(KM). This function should be used only to implement
     * the logic of communication with KM.
     *
     * @param consumerKey consumer key application of the application to be retrieved from KM
     * @return retrieved oauth application
     */
    private org.wso2.carbon.apimgt.api.model.xsd.OAuthApplicationInfo getOAuthAppFromKM(String consumerKey) {
        // TODO: 8/17/18 Send get oauth application request to actual KM

        // Retrieve sample in-memory oauth application
        return oauthApps.get(consumerKey);
    }

    /**
     * Parse and retrieve the sigend JWT from the access token string
     *
     * @param accessToken JWT Access Token
     * @return {@link SignedJWT} model of the {@code accessToken}
     * @throws ParseException when failed to parse the access token as an JWT
     */
    private SignedJWT getSignedJWT(String accessToken) throws ParseException {
        return SignedJWT.parse(accessToken);
    }

    /**
     * Common method to log and throw exceptions.
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
