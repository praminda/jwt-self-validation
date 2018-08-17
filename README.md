# README

This project is compatible only with WSO2 API Manager 2.1.0. If support for other versions is required, update the dependency versions to respective release component version.

## How To Run

1. Build the project with `mvn clean install` command.
1. Copy paste the built .jar file into <APIM_HOME>/repository/components/lib
1. Set `org.wso2.apimgt.sample.OAuth2JWTSelfValidationHandler` as token validator.
1. Set `org.wso2.apimgt.sample.ExternalKeyManager` as KeyManagerClientImpl.
1. Set `org.wso2.apimgt.sample.JWTScopeValidator` as the Scope Validator.
1. Start the WSO2 APIM 2.1.0 server and test.