/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0.
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 * ******************************************************************************
 */

package org.eclipse.tractusx.wallet.stub.edc;


import com.nimbusds.jwt.JWTClaimsSet;
import lombok.SneakyThrows;
import org.eclipse.tractusx.wallet.stub.runtime.postgresql.WalletStubApplication;
import org.eclipse.tractusx.wallet.stub.config.TestContextInitializer;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.CreateCredentialWithScopeRequest;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.CreateCredentialWithoutScopeRequest;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.QueryPresentationRequest;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.QueryPresentationResponse;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.StsTokeResponse;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.api.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.test.TestUtils;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = { WalletStubApplication.class })
@ContextConfiguration(initializers = { TestContextInitializer.class })
class EDCTest {

    public static final String BEARER = "Bearer ";
    public static final String VERIFIABLE_CREDENTIAL = "verifiableCredential";
    public static final String CREDENTIAL_SUBJECT = "credentialSubject";
    public static final String ISSUER = "issuer";
    public static final String CONSUMER_DID = "consumerDid";
    public static final String PROVIDER_DID = "providerDid";
    @Autowired
    private WalletStubSettings walletStubSettings;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private TokenSettings tokenSettings;

    @Autowired
    private KeyService keyService;

    @Autowired
    private DidDocumentService didDocumentService;

    private static @NotNull QueryPresentationResponse validateResponseFormat(ResponseEntity<QueryPresentationResponse> response) {
        QueryPresentationResponse responseBody = response.getBody();
        Assertions.assertNotNull(responseBody);

        Assertions.assertEquals(1, responseBody.getPresentation().size());

        Assertions.assertEquals(1, responseBody.getContexts().size());
        Assertions.assertEquals("PresentationResponseMessage", responseBody.getType());
        return responseBody;
    }

    private static QueryPresentationRequest getQueryPresentationRequest(List<String> vcTypes) throws URISyntaxException {
        return QueryPresentationRequest.builder()
                .scope(vcTypes.stream().map(vc -> "org.eclipse.tractusx.vc.type:" + vc + ":read").toList())
                .type("PresentationQueryMessage")
                .contexts(List.of(new URI("https://identity.foundation/presentation-exchange/submission/v1"), new URI("https://w3id.org/tractusx-trust/v0.8")))
                .build();
    }

    @SuppressWarnings("unchecked")
    @SneakyThrows
    @Test
    @DisplayName("Test Query presentation API  without scoped STS(ie. create STS without scope and query presentation)")
    void testQueryPresentationWithoutScopedSTS() {
        String readScope = "read";
        String consumerBpn = TestUtils.getRandomBpmNumber();
        String providerBpn = TestUtils.getRandomBpmNumber();
        String consumerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), consumerBpn);
        String providerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), providerBpn);

        String requestedInnerToken = getToken(consumerDid, providerDid, consumerBpn, readScope, List.of(Constants.BPN_CREDENTIAL, Constants.DATA_EXCHANGE_CREDENTIAL));
        String jwt = createStsWithoutScope(consumerDid, providerDid, consumerBpn, requestedInnerToken);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, BEARER + jwt);

        QueryPresentationRequest request = getQueryPresentationRequest(List.of(Constants.BPN_CREDENTIAL, Constants.DATA_EXCHANGE_CREDENTIAL));

        HttpEntity<QueryPresentationRequest> entity = new HttpEntity<>(request, headers);
        ResponseEntity<QueryPresentationResponse> response = restTemplate.exchange("/api/presentations/query", HttpMethod.POST, entity, QueryPresentationResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());

        QueryPresentationResponse responseBody = validateResponseFormat(response);
        String vpToken = responseBody.getPresentation().getFirst();
        JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(vpToken);

        Assertions.assertTrue(jwtClaimsSet.getAudience().contains(consumerDid));
        Assertions.assertEquals(jwtClaimsSet.getSubject(), consumerDid);
        Assertions.assertEquals(jwtClaimsSet.getIssuer(), consumerDid);

        Assertions.assertEquals(jwtClaimsSet.getStringClaim(Constants.BPN), consumerBpn);

        Assertions.assertNotNull(jwtClaimsSet.getJSONObjectClaim(Constants.VP));

        Map<String, Object> vp = jwtClaimsSet.getJSONObjectClaim(Constants.VP);

        Assertions.assertTrue(vp.containsKey(VERIFIABLE_CREDENTIAL));

        List<String> vcs = (List<String>) vp.get(VERIFIABLE_CREDENTIAL);

        Assertions.assertEquals(2, vcs.size());

        String vc = vcs.getFirst();

        JWTClaimsSet vcClaims = tokenService.verifyTokenAndGetClaims(vc);

        Assertions.assertTrue(vcClaims.getAudience().contains(consumerDid));
        Assertions.assertEquals(vcClaims.getSubject(), CommonUtils.getDidWeb(walletStubSettings.didHost(), walletStubSettings.baseWalletBPN()));
        Assertions.assertEquals(vcClaims.getIssuer(), CommonUtils.getDidWeb(walletStubSettings.didHost(), walletStubSettings.baseWalletBPN()));

        Assertions.assertNotNull(vcClaims.getJSONObjectClaim(Constants.VC));

        Map<String, Object> jsonLdVc = vcClaims.getJSONObjectClaim(Constants.VC);
        Map<String, String> subject = (Map<String, String>) jsonLdVc.get(CREDENTIAL_SUBJECT);
        Assertions.assertEquals(subject.get(Constants.HOLDER_IDENTIFIER), consumerBpn);
        Assertions.assertEquals(subject.get(Constants.ID), consumerDid);
        Assertions.assertEquals(jsonLdVc.get(ISSUER).toString(), CommonUtils.getDidWeb(walletStubSettings.didHost(), walletStubSettings.baseWalletBPN()));


        vc = vcs.getLast();

        vcClaims = tokenService.verifyTokenAndGetClaims(vc);

        Assertions.assertTrue(vcClaims.getAudience().contains(consumerDid));
        Assertions.assertEquals(vcClaims.getSubject(), CommonUtils.getDidWeb(walletStubSettings.didHost(), walletStubSettings.baseWalletBPN()));
        Assertions.assertEquals(vcClaims.getIssuer(), CommonUtils.getDidWeb(walletStubSettings.didHost(), walletStubSettings.baseWalletBPN()));

        Assertions.assertNotNull(vcClaims.getJSONObjectClaim(Constants.VC));

        jsonLdVc = vcClaims.getJSONObjectClaim(Constants.VC);
        subject = (Map<String, String>) jsonLdVc.get(CREDENTIAL_SUBJECT);
        Assertions.assertEquals(subject.get(Constants.HOLDER_IDENTIFIER), consumerBpn);
        Assertions.assertEquals(subject.get(Constants.ID), consumerDid);
        Assertions.assertNotNull(subject.get(Constants.GROUP));
        Assertions.assertNotNull(subject.get(Constants.USE_CASE));
        Assertions.assertNotNull(subject.get(Constants.CONTRACT_TEMPLATE));
        Assertions.assertNotNull(subject.get(Constants.CONTRACT_VERSION));
        Assertions.assertEquals(jsonLdVc.get(ISSUER).toString(), CommonUtils.getDidWeb(walletStubSettings.didHost(), walletStubSettings.baseWalletBPN()));
    }

    @SuppressWarnings("unchecked")
    @SneakyThrows
    @Test
    @DisplayName("Test Query presentation API  with scoped STS(ie. create STS with scope and query presentation)")
    void testQueryPresentationWithScopedSTS() {
        String readScope = "read";
        String consumerBpn = TestUtils.getRandomBpmNumber();
        String providerBpn = TestUtils.getRandomBpmNumber();
        String consumerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), consumerBpn);
        String providerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), providerBpn);
        String jwt = createStsWithScope(readScope, consumerDid, providerDid, consumerBpn, new String[]{ Constants.MEMBERSHIP_CREDENTIAL });
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, BEARER + jwt);

        QueryPresentationRequest request = getQueryPresentationRequest(List.of(Constants.MEMBERSHIP_CREDENTIAL));

        HttpEntity<QueryPresentationRequest> entity = new HttpEntity<>(request, headers);
        ResponseEntity<QueryPresentationResponse> response = restTemplate.exchange("/api/presentations/query", HttpMethod.POST, entity, QueryPresentationResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());

        QueryPresentationResponse responseBody = validateResponseFormat(response);

        String vpToken = responseBody.getPresentation().getFirst();
        JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(vpToken);

        Assertions.assertTrue(jwtClaimsSet.getAudience().contains(providerDid));
        Assertions.assertEquals(jwtClaimsSet.getSubject(), consumerDid);
        Assertions.assertEquals(jwtClaimsSet.getIssuer(), consumerDid);

        Assertions.assertEquals(jwtClaimsSet.getStringClaim(Constants.BPN), consumerBpn);

        Assertions.assertNotNull(jwtClaimsSet.getJSONObjectClaim(Constants.VP));

        Map<String, Object> vp = jwtClaimsSet.getJSONObjectClaim(Constants.VP);

        Assertions.assertTrue(vp.containsKey(VERIFIABLE_CREDENTIAL));

        List<String> vcs = (List<String>) vp.get(VERIFIABLE_CREDENTIAL);

        Assertions.assertEquals(1, vcs.size());

        String vc = vcs.getFirst();

        JWTClaimsSet vcClaims = tokenService.verifyTokenAndGetClaims(vc);

        Assertions.assertTrue(vcClaims.getAudience().contains(consumerDid));
        Assertions.assertEquals(vcClaims.getSubject(), CommonUtils.getDidWeb(walletStubSettings.didHost(), walletStubSettings.baseWalletBPN()));
        Assertions.assertEquals(vcClaims.getIssuer(), CommonUtils.getDidWeb(walletStubSettings.didHost(), walletStubSettings.baseWalletBPN()));

        Assertions.assertNotNull(vcClaims.getJSONObjectClaim(Constants.VC));

        Map<String, Object> jsonLdVc = vcClaims.getJSONObjectClaim(Constants.VC);
        Map<String, String> subject = (Map<String, String>) jsonLdVc.get(CREDENTIAL_SUBJECT);
        Assertions.assertEquals(subject.get(Constants.HOLDER_IDENTIFIER), consumerBpn);
        Assertions.assertEquals(subject.get(Constants.ID), consumerDid);
        Assertions.assertEquals(jsonLdVc.get(ISSUER).toString(), CommonUtils.getDidWeb(walletStubSettings.didHost(), walletStubSettings.baseWalletBPN()));
    }

    @SneakyThrows
    @Test
    @DisplayName("Create STS token without scope and validate")
    void testCreateStsWithoutScope() {
        String readScope = "read";
        String consumerBpn = TestUtils.getRandomBpmNumber();
        String providerBpn = TestUtils.getRandomBpmNumber();
        String consumerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), consumerBpn);
        String providerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), providerBpn);
        //create token
        String requestedInnerToken = getToken(consumerDid, providerDid, consumerBpn, readScope, List.of(Constants.MEMBERSHIP_CREDENTIAL));

        String stsToken = createStsWithoutScope(consumerDid, providerDid, consumerBpn, requestedInnerToken);
        //validate STS
        JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(stsToken);
        Assertions.assertEquals(jwtClaimsSet.getClaim(Constants.BPN).toString(), consumerBpn);
        Assertions.assertEquals(jwtClaimsSet.getAudience().getFirst(), consumerDid);
        Assertions.assertEquals(jwtClaimsSet.getIssuer(), consumerDid);
        Assertions.assertEquals(jwtClaimsSet.getSubject(), consumerDid);

        //validate inner token
        Assertions.assertNotNull(jwtClaimsSet.getStringClaim(Constants.TOKEN));
        String innerToken = jwtClaimsSet.getStringClaim(Constants.TOKEN);

        Assertions.assertEquals(requestedInnerToken, innerToken);
        JWTClaimsSet innerTokenClaim = tokenService.verifyTokenAndGetClaims(innerToken);
        Assertions.assertEquals(innerTokenClaim.getClaim(Constants.BPN).toString(), consumerBpn);
        Assertions.assertEquals(innerTokenClaim.getClaim(CONSUMER_DID).toString(), consumerDid);
        Assertions.assertEquals(innerTokenClaim.getClaim(PROVIDER_DID).toString(), providerDid);
        Assertions.assertEquals(innerTokenClaim.getClaim(Constants.SCOPE).toString(), readScope);
        Assertions.assertEquals(innerTokenClaim.getAudience().getFirst(), consumerDid);
        Assertions.assertEquals(innerTokenClaim.getSubject(), consumerDid);
        Assertions.assertEquals(Constants.MEMBERSHIP_CREDENTIAL, innerTokenClaim.getStringListClaim(Constants.CREDENTIAL_TYPES).getFirst());
    }

    //CS-4559
    @SneakyThrows
    @Test
    @DisplayName("Create STS token without scope and validate, try to add token which signature verification gets failed")
    void testCreateStsWithoutScopeWhenInnerTokenValidationFailed() {
        String consumerBpn = TestUtils.getRandomBpmNumber();
        String providerBpn = "BPNL000000004OUP";
        String consumerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), consumerBpn);
        String providerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), providerBpn);

        //Sample inner token which signature verification gets failed
        String requestedInnerToken = "eyJraWQiOiJ0cmFuc2Zlci1wcm94eS10b2tlbi1zaWduZXItcHVibGljLWtleSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJCUE5MMDAwMDAwMDA0T1VQIiwiYXVkIjoiQlBOTDAwMDAwMDAwNE9VUCIsInN1YiI6IkJQTkwwMDAwMDAwMDRPVVAiLCJleHAiOjE3NjMzNzc1MTQsImlhdCI6MTc2MzM3NzIxNCwianRpIjoiYTY1NjNmOWMtZjk2ZC00N2YwLWE3YzAtNmEzNTFjMTcwMTcwIn0.IX_Yr1zsE0tQgFycxotWYG8gGg_7eW9cO9YS4QZJEyvW7ixmUehwukc1_o-1hc9_QKyCwGGctjtRKim4gJCwaYprRfwuNIWj98xMtsBIWPpe9aid8AWnuHp5eOXdgnx78KGAf2Btbu-2y4K8Y3Sug7jL5Kjnf88kahYwzR93np95VhVtkOezMkK5JSIv46D-JtBDQi3nr3FddcidrKogt3BwEMbG7rFlFhFyCedaRW4L8uUzqI3Q7W4oX6NirLRtaDN7WhQZKg4pgNLUEozGMOVSMtEx1ARdW56F8EeAD5K9pulG1Gl4QSq9O9BO-PEOfxzv9991aE8ylsAPxM3ctKuntjGvCRL28wAmZvy0P6tijBJxHbeaw6qDG-syXO45M9-qvx96tQCy2JniPzBjtYctlCJ86lpWHeghaf07IgWXwTcw-17RCzjnAGHj8aLjhiOV2GZCPAA2DfYn3uvU8syNez6nRzgJ8vwpQSpXyoOivfy5klRpB9csFBJesaBGQCJNDzPVcqydE2Kq44o2BzZRTC220hGru0-30fqQ-ORhzgXSybMxUzaN14AW-iaQHyJs4Paw0F_pdXpsfgUX2WIl6pDjqKi-f_DnIFK9G07t7uSa0WapKBcKb3tikQPiGdDdKais_JZJIZ27Hn9mFtdY_LrrOyVvMFNFfb05W3g";

        String stsToken = createStsWithoutScope(consumerDid, providerDid, consumerBpn, requestedInnerToken);
        //validate STS
        JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(stsToken);
        Assertions.assertEquals(jwtClaimsSet.getClaim(Constants.BPN).toString(), consumerBpn);
        Assertions.assertEquals(jwtClaimsSet.getAudience().getFirst(), providerDid);
        Assertions.assertEquals(jwtClaimsSet.getIssuer(), consumerDid);
        Assertions.assertEquals(jwtClaimsSet.getSubject(), consumerDid);
    }

    @SneakyThrows
    @Test
    @DisplayName("Test creating STS token without audience claim should fail")
    void testCreateStsWithoutAudience() {
        String readScope = "read";
        String consumerBpn = TestUtils.getRandomBpmNumber();
        String providerBpn = TestUtils.getRandomBpmNumber();
        String consumerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), consumerBpn);
        String providerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), providerBpn);

        // Create token without audience
        JWTClaimsSet tokenWithoutAudience = new JWTClaimsSet.Builder()
                .issuer(consumerDid)
                .subject(consumerDid)
                .issueTime(Date.from(Instant.now()))
                .claim(Constants.CREDENTIAL_TYPES, List.of(Constants.MEMBERSHIP_CREDENTIAL))
                .claim(Constants.SCOPE, readScope)
                .claim(CONSUMER_DID, consumerDid)
                .claim(PROVIDER_DID, providerDid)
                .claim(Constants.BPN, consumerBpn)
                .build();

        String tokenWithoutAudienceStr = CommonUtils.signedJWT(tokenWithoutAudience,
                        keyService.getKeyPair(consumerBpn),
                        didDocumentService.getOrCreateDidDocument(consumerBpn).getVerificationMethod().getFirst().getId())
                .serialize();

        // Attempt to create STS without audience should fail
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(consumerBpn, restTemplate, tokenService, tokenSettings));

        CreateCredentialWithoutScopeRequest request = CreateCredentialWithoutScopeRequest.builder()
                .signToken(CreateCredentialWithoutScopeRequest.SignToken.builder()
                        .audience(consumerDid)
                        .subject(providerDid)
                        .issuer(providerDid)
                        .token(tokenWithoutAudienceStr)
                        .build())
                .build();

        HttpEntity<CreateCredentialWithoutScopeRequest> entity = new HttpEntity<>(request, headers);

        ResponseEntity<StsTokeResponse> response = restTemplate.exchange("/api/sts",
                HttpMethod.POST, entity, StsTokeResponse.class);

        Assertions.assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatusCode().value());
    }

    @SneakyThrows
    @Test
    @DisplayName("Create STS token with scope and validate")
    void testCreateSTSTokenWithScope() {
        String readScope = "read";
        String consumerBpn = TestUtils.getRandomBpmNumber();
        String providerBpn = TestUtils.getRandomBpmNumber();
        String consumerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), consumerBpn);
        String providerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), providerBpn);
        String jwt = createStsWithScope(readScope, consumerDid, providerDid, consumerBpn, new String[]{ Constants.MEMBERSHIP_CREDENTIAL });

        //validate STS
        JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(jwt);
        Assertions.assertEquals(jwtClaimsSet.getClaim(Constants.BPN).toString(), providerBpn);
        Assertions.assertEquals(jwtClaimsSet.getAudience().getFirst(), providerDid);
        Assertions.assertEquals(jwtClaimsSet.getIssuer(), consumerDid);

        //validate inner token
        Assertions.assertNotNull(jwtClaimsSet.getStringClaim(Constants.TOKEN));
        String innerToken = jwtClaimsSet.getStringClaim(Constants.TOKEN);
        JWTClaimsSet innerTokenClaim = tokenService.verifyTokenAndGetClaims(innerToken);
        Assertions.assertEquals(innerTokenClaim.getClaim(Constants.BPN).toString(), consumerBpn);
        Assertions.assertEquals(innerTokenClaim.getClaim(CONSUMER_DID).toString(), consumerDid);
        Assertions.assertEquals(innerTokenClaim.getClaim(PROVIDER_DID).toString(), providerDid);
        Assertions.assertEquals(innerTokenClaim.getClaim(Constants.SCOPE).toString(), readScope);
        Assertions.assertEquals(innerTokenClaim.getAudience().getFirst(), providerDid);
        Assertions.assertEquals(innerTokenClaim.getSubject(), consumerDid);
        Assertions.assertEquals(Constants.MEMBERSHIP_CREDENTIAL, innerTokenClaim.getStringListClaim(Constants.CREDENTIAL_TYPES).getFirst());
    }

    private String createStsWithScope(String readScope, String consumerDid, String providerDid, String consumerBpn, String[] vcTypes) {
        CreateCredentialWithScopeRequest withScopeRequest = CreateCredentialWithScopeRequest.builder()
                .grantAccess(CreateCredentialWithScopeRequest.GrantAccess.builder()
                        .scope(readScope)
                        .consumerDid(consumerDid)
                        .providerDid(providerDid)
                        .credentialTypes(vcTypes)
                        .build())
                .build();

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(consumerBpn, restTemplate, tokenService, tokenSettings));
        HttpEntity<CreateCredentialWithScopeRequest> entity = new HttpEntity<>(withScopeRequest, headers);
        ResponseEntity<StsTokeResponse> response = restTemplate.exchange("/api/sts", HttpMethod.POST, entity, StsTokeResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());

        Assertions.assertNotNull(response.getBody());
        return response.getBody().getJwt();
    }

    private String getToken(String consumerDid, String providerDid, String consumerBpn, String scope, List<String> vcTypes) {
        JWTClaimsSet tokeJwtClaimsSet = new JWTClaimsSet.Builder()
                .issuer(consumerDid)
                .audience(consumerDid)
                .subject(consumerDid)
                .issueTime(Date.from(Instant.now()))
                .claim(Constants.CREDENTIAL_TYPES, vcTypes)
                .claim(Constants.SCOPE, scope)
                .claim(CONSUMER_DID, consumerDid)
                .claim(PROVIDER_DID, providerDid)
                .claim(Constants.BPN, consumerBpn)
                .build();
        return CommonUtils.signedJWT(tokeJwtClaimsSet, keyService.getKeyPair(consumerBpn), didDocumentService.getOrCreateDidDocument(consumerBpn).getVerificationMethod().getFirst().getId()).serialize();
    }


    private String createStsWithoutScope(String consumerDid, String providerDid, String consumerBpn, String token) {

        CreateCredentialWithoutScopeRequest request = CreateCredentialWithoutScopeRequest.builder()
                .signToken(CreateCredentialWithoutScopeRequest.SignToken.builder()
                        .audience(consumerDid)
                        .subject(providerDid)
                        .issuer(providerDid)
                        .token(token)
                        .build())
                .build();

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(consumerBpn, restTemplate, tokenService, tokenSettings));
        HttpEntity<CreateCredentialWithoutScopeRequest> entity = new HttpEntity<>(request, headers);
        ResponseEntity<StsTokeResponse> response = restTemplate.exchange("/api/sts", HttpMethod.POST, entity, StsTokeResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());

        Assertions.assertNotNull(response.getBody());
        return response.getBody().getJwt();
    }
}
