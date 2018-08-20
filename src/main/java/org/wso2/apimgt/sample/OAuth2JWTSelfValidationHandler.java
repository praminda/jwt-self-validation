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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.dto.APIKeyValidationInfoDTO;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.apimgt.keymgt.APIKeyMgtException;
import org.wso2.carbon.apimgt.keymgt.handlers.AbstractKeyValidationHandler;
import org.wso2.carbon.apimgt.keymgt.service.TokenValidationContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class OAuth2JWTSelfValidationHandler extends AbstractKeyValidationHandler {
    private static final Log log = LogFactory.getLog(OAuth2JWTSelfValidationHandler.class);
    private static final String OIDC_IDP_ENTITY_ID = "IdPEntityId";
    private static final String ALGO_PREFIX = "RS";

    public OAuth2JWTSelfValidationHandler() {
        log.info(this.getClass().getName() + " Initialised");
    }

    @Override
    public boolean validateToken(TokenValidationContext tokenValidationContext) throws APIKeyMgtException {
        boolean isJWTValid, isValidSignature, isValidNotBeforeTime, isNotExpired;
        AccessTokenInfo tokenInfo;

        try {
            SignedJWT signedJWT = getSignedJWT(tokenValidationContext.getAccessToken());
            ReadOnlyJWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            if (claimsSet == null) {
                throw new APIKeyMgtException("Claim values are empty in the given Token.");
            }

            // validate jwt fields
            validateRequiredFields(claimsSet);
            IdentityProvider identityProvider = getResidentIDPForIssuer(claimsSet.getIssuer());

            // validate jwt signature
            isValidSignature = validateSignature(signedJWT, identityProvider);

            // check JWT Expiration and note before time
            isNotExpired = checkExpirationTime(claimsSet.getExpirationTime());
            isValidNotBeforeTime = checkNotBeforeTime(claimsSet.getNotBeforeTime());
        } catch (JOSEException | ParseException | IdentityOAuth2Exception e) {
            throw new APIKeyMgtException("Error while validating Token.", e);
        }

        // Token is valid only if below 3 conditions are met
        isJWTValid = isValidSignature && isNotExpired && isValidNotBeforeTime;

        try {
            // Obtaining details about the token from KM
            tokenInfo = KeyManagerHolder.getKeyManagerInstance().
                    getTokenMetaData(tokenValidationContext.getAccessToken());

            if (tokenInfo == null) {
                return false;
            }
            tokenInfo.setTokenValid(isJWTValid);

            // Setting TokenInfo in validationContext. Methods down in the chain can use TokenInfo.
            tokenValidationContext.setTokenInfo(tokenInfo);
            APIKeyValidationInfoDTO apiKeyValidationInfoDTO = new APIKeyValidationInfoDTO();
            tokenValidationContext.setValidationInfoDTO(apiKeyValidationInfoDTO);

            if (!tokenInfo.isTokenValid()) {
                apiKeyValidationInfoDTO.setAuthorized(false);

                if (tokenInfo.getErrorcode() > 0) {
                    apiKeyValidationInfoDTO.setValidationStatus(tokenInfo.getErrorcode());
                } else {
                    apiKeyValidationInfoDTO.setValidationStatus(APIConstants.KeyValidationStatus.
                            API_AUTH_GENERAL_ERROR);
                }

                return false;
            }

            apiKeyValidationInfoDTO.setAuthorized(tokenInfo.isTokenValid());
            apiKeyValidationInfoDTO.setEndUserName(tokenInfo.getEndUserName());
            apiKeyValidationInfoDTO.setConsumerKey(tokenInfo.getConsumerKey());
            apiKeyValidationInfoDTO.setIssuedTime(tokenInfo.getIssuedTime());
            apiKeyValidationInfoDTO.setValidityPeriod(tokenInfo.getValidityPeriod());

            if (tokenInfo.getScopes() != null) {
                Set<String> scopeSet = new HashSet<String>(Arrays.asList(tokenInfo.getScopes()));
                apiKeyValidationInfoDTO.setScopes(scopeSet);
            }
        } catch (APIManagementException e) {
            log.error("Error while obtaining Token Metadata from Authorization Server", e);
            throw new APIKeyMgtException("Error while obtaining Token Metadata from Authorization Server");
        }

        return tokenInfo.isTokenValid();
    }

    @Override
    public boolean validateScopes(TokenValidationContext validationContext) throws APIKeyMgtException {
        boolean isValid = false;
        APIKeyValidationInfoDTO apiKeyValidationInfoDTO = validationContext.getValidationInfoDTO();

        if (apiKeyValidationInfoDTO == null) {
            throw new APIKeyMgtException("Key Validation information not set");
        }

        String[] scopes = null;
        Set<String> scopesSet = apiKeyValidationInfoDTO.getScopes();

        // Convert scopesSet to string array
        if (scopesSet != null && !scopesSet.isEmpty()) {
            scopes = scopesSet.toArray(new String[scopesSet.size()]);

            if (log.isDebugEnabled() && scopes != null) {
                StringBuilder scopeList = new StringBuilder();

                for (String scope : scopes) {
                    scopeList.append(scope);
                    scopeList.append(",");
                }

                scopeList.deleteCharAt(scopeList.length() - 1);
                log.debug("Scopes allowed for token : " + validationContext.getAccessToken() + " : " + scopeList
                        .toString());
            }
        }

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(apiKeyValidationInfoDTO.getEndUserName());
        AccessTokenDO accessTokenDO = new AccessTokenDO(apiKeyValidationInfoDTO.getConsumerKey(), user, scopes, null,
                null, apiKeyValidationInfoDTO.getValidityPeriod(), apiKeyValidationInfoDTO.getValidityPeriod(),
                apiKeyValidationInfoDTO.getType());
        accessTokenDO.setAccessToken(validationContext.getAccessToken());

        String actualVersion = validationContext.getVersion();

        // Check if the api version has been prefixed with _default_
        if (actualVersion != null && actualVersion.startsWith(APIConstants.DEFAULT_VERSION_PREFIX)) {

            // Remove the prefix from the version.
            actualVersion = actualVersion.split(APIConstants.DEFAULT_VERSION_PREFIX)[1];
        }

        // build the resource path being accessed
        String resource =
                validationContext.getContext() + '/' + actualVersion + validationContext.getMatchingResource() + ':'
                        + validationContext.getHttpVerb();

        try {
            OAuth2ScopeValidator scopeValidator = OAuthServerConfiguration.getInstance().getoAuth2ScopeValidator();

            if (scopeValidator != null) {

                // Validate scopes using JWTScopeValidator
                if (scopeValidator.validateScope(accessTokenDO, resource)) {
                    isValid = true;
                } else {
                    apiKeyValidationInfoDTO.setAuthorized(false);
                    apiKeyValidationInfoDTO.setValidationStatus(APIConstants.KeyValidationStatus.INVALID_SCOPE);
                }
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("ERROR while validating token scope " + e.getMessage(), e);
            apiKeyValidationInfoDTO.setAuthorized(false);
            apiKeyValidationInfoDTO.setValidationStatus(APIConstants.KeyValidationStatus.INVALID_SCOPE);
        }

        return isValid;
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
     * Checks if following fields contain values in the JWT claim set
     * <ul>
     *     <li>issuer</li>
     *     <li>subject</li>
     *     <li>expiration time</li>
     *     <li>audience</li>
     *     <li>jti</li>
     * </ul>
     *
     * @param claimsSet JWT claim set to validate
     * @return {@code true} if validation is successful
     * @throws APIKeyMgtException When validation fails
     */
    private boolean validateRequiredFields(ReadOnlyJWTClaimsSet claimsSet) throws APIKeyMgtException {
        String subject = claimsSet.getSubject();
        List<String> audience = claimsSet.getAudience();
        String jti = claimsSet.getJWTID();

        if (StringUtils.isEmpty(claimsSet.getIssuer()) || StringUtils.isEmpty(subject)
                || claimsSet.getExpirationTime() == null || audience == null || jti == null) {
            throw new APIKeyMgtException("Mandatory fields(Issuer, Subject, Expiration time,"
                    + " jtl or Audience) are empty in the given Token.");
        }

        return true;
    }

    /**
     * Retrieve resident IDP for the issuer
     *
     * @param jwtIssuer issuer of the JWT
     * @return Resident IDP
     * @throws APIKeyMgtException
     */
    private IdentityProvider getResidentIDPForIssuer(String jwtIssuer) throws APIKeyMgtException {
        String tenantDomain = getTenantDomain();
        String issuer = StringUtils.EMPTY;
        IdentityProvider residentIdentityProvider;

        try {
            residentIdentityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg = String
                    .format("Error while getting Resident Identity Provider of '%s' tenant.", tenantDomain);
            throw new APIKeyMgtException(errorMsg, e);
        }

        FederatedAuthenticatorConfig[] fedAuthnConfigs = residentIdentityProvider.getFederatedAuthenticatorConfigs();
        FederatedAuthenticatorConfig oauthAuthenticatorConfig = IdentityApplicationManagementUtil
                .getFederatedAuthenticator(fedAuthnConfigs, IdentityApplicationConstants.Authenticator.OIDC.NAME);

        if (oauthAuthenticatorConfig != null) {
            issuer = IdentityApplicationManagementUtil
                    .getProperty(oauthAuthenticatorConfig.getProperties(), OIDC_IDP_ENTITY_ID).getValue();
        }

        if (!jwtIssuer.equals(issuer)) {
            throw new APIKeyMgtException("No Registered IDP found for the token with issuer name : " + jwtIssuer);
        }

        return residentIdentityProvider;
    }

    /**
     * @return current tenant domain
     */
    private String getTenantDomain() {
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        return tenantDomain;
    }

    /**
     * Validates JWT signature against the {@code idp}
     *
     * @param signedJWT JWT to be validated
     * @param idp IDP to validate against
     * @return validation status
     * @throws JOSEException
     * @throws IdentityOAuth2Exception
     */
    private boolean validateSignature(SignedJWT signedJWT, IdentityProvider idp)
            throws JOSEException, IdentityOAuth2Exception {
        JWSVerifier verifier = null;
        X509Certificate x509Certificate = resolveSignerCertificate(idp);
        if (x509Certificate == null) {
            throw new IdentityOAuth2Exception(
                    "Unable to locate certificate for Identity Provider: " + idp.getDisplayName());
        }

        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            throw new IdentityOAuth2Exception("Algorithm must not be null.");

        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm found in the Token Header: " + alg);
            }
            if (alg.indexOf(ALGO_PREFIX) == 0) {

                // At this point 'x509Certificate' will never be null.
                PublicKey publicKey = x509Certificate.getPublicKey();

                if (publicKey instanceof RSAPublicKey) {
                    verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                } else {
                    throw new IdentityOAuth2Exception("Public key is not an RSA public key.");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Algorithm not supported yet: " + alg);
                }
            }
            if (verifier == null) {
                throw new IdentityOAuth2Exception("Could not create a signature verifier for algorithm type: " + alg);
            }
        }

        boolean isValid = signedJWT.verify(verifier);
        if (log.isDebugEnabled()) {
            log.debug("Signature verified: " + isValid);
        }
        return isValid;
    }

    /**
     * Retrieve IDP certificate as {@code X509Certificate}
     *
     * @param idp IDP instance
     * @return resovled {@code X509Certificate}
     * @throws IdentityOAuth2Exception
     */
    private X509Certificate resolveSignerCertificate(IdentityProvider idp) throws IdentityOAuth2Exception {
        X509Certificate x509Certificate;
        String tenantDomain = getTenantDomain();
        try {
            x509Certificate = (X509Certificate) IdentityApplicationManagementUtil
                    .decodeCertificate(idp.getCertificate());
        } catch (CertificateException e) {
            throw new IdentityOAuth2Exception(
                    "Error occurred while decoding public certificate of Identity Provider " + idp
                            .getIdentityProviderName() + " for tenant domain " + tenantDomain, e);
        }
        return x509Certificate;
    }

    /**
     * Check if expiration time is already reached or not
     *
     * @param expirationTime expiration time of the JWT
     * @return validation status. {@code true} or {@code false}
     */
    private boolean checkExpirationTime(Date expirationTime) {
        long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        long expirationTimeInMillis = expirationTime.getTime();
        long currentTimeInMillis = System.currentTimeMillis();

        if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
            if (log.isDebugEnabled()) {
                log.debug("Token is expired." + ", Expiration Time(ms) : " + expirationTimeInMillis
                        + ", TimeStamp Skew : " + timeStampSkewMillis + ", Current Time : " + currentTimeInMillis
                        + ". Token Rejected and validation terminated.");
            }

            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Expiration Time(exp) of Token was validated successfully.");
        }

        return true;
    }

    /**
     * Check if token is used before notBeforeTime
     *
     * @param notBeforeTime not before time of the JWT
     * @return validation status. {@code true} or {@code false}
     */
    private boolean checkNotBeforeTime(Date notBeforeTime) {
        if (notBeforeTime != null) {
            long timeStampSkewMillis = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
            long notBeforeTimeMillis = notBeforeTime.getTime();
            long currentTimeInMillis = System.currentTimeMillis();

            if (currentTimeInMillis + timeStampSkewMillis < notBeforeTimeMillis) {
                if (log.isDebugEnabled()) {
                    log.debug("Token is used before Not_Before_Time." + ", Not Before Time(ms) : " + notBeforeTimeMillis
                            + ", TimeStamp Skew : " + timeStampSkewMillis + ", Current Time : " + currentTimeInMillis
                            + ". Token Rejected and validation terminated.");
                }

                return false;
            }

            if (log.isDebugEnabled()) {
                log.debug("Not Before Time(nbf) of Token was validated successfully.");
            }
        }

        return true;
    }
}
