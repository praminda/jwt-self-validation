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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ResourceScopeCacheEntry;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class JWTScopeValidator extends OAuth2ScopeValidator {
    private static final Log log = LogFactory.getLog(JWTScopeValidator.class);

    @Override
    public boolean validateScope(AccessTokenDO accessTokenDO, String resource) throws IdentityOAuth2Exception {
        // Get the list of scopes associated with the access token
        String[] scopes = accessTokenDO.getScope();

        // If no scopes are associated with the token no need to perform scope validation
        if (scopes == null || scopes.length == 0) {
            return true;
        }

        String resourceScope = null;
        TokenMgtDAO tokenMgtDAO = new TokenMgtDAO();
        boolean cacheHit = false;

        // Check the cache, if caching is enabled.
        if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
            OAuthCache oauthCache = OAuthCache.getInstance();
            OAuthCacheKey cacheKey = new OAuthCacheKey(resource);
            CacheEntry result = oauthCache.getValueFromCache(cacheKey);

            // Cache hit
            if (result instanceof ResourceScopeCacheEntry) {
                resourceScope = ((ResourceScopeCacheEntry) result).getScope();
                cacheHit = true;
            }
        }

        if (!cacheHit) {
            resourceScope = tokenMgtDAO.findScopeOfResource(resource);

            if (OAuthServerConfiguration.getInstance().isCacheEnabled()) {
                OAuthCache oauthCache = OAuthCache.getInstance();
                OAuthCacheKey cacheKey = new OAuthCacheKey(resource);
                ResourceScopeCacheEntry cacheEntry = new ResourceScopeCacheEntry(resourceScope);

                // Store resourceScope in cache even if it is null (to avoid database calls when accessing resources
                // for which scopes haven't been defined).
                oauthCache.addToCache(cacheKey, cacheEntry);
            }
        }

        // return true if resource is not protected by scopes
        if (resourceScope == null) {
            if (log.isDebugEnabled()) {
                log.debug("Resource '" + resource + "' is not protected with a scope");
            }

            return true;
        }

        List<String> scopeList = new ArrayList<>(Arrays.asList(scopes));

        // Token doesn't bear the scopes required to access the resource
        if (!scopeList.contains(resourceScope)) {
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Access token '" + accessTokenDO.getAccessToken() + "' does not bear the scope '"
                        + resourceScope + "'");
            }

            return false;
        }

        return true;
    }
}
