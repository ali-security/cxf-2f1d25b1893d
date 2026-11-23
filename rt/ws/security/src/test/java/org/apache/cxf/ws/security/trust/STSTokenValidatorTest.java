/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.cxf.ws.security.trust;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.cxf.common.util.Base64Utility;
import org.apache.cxf.endpoint.Endpoint;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.ExchangeImpl;
import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageImpl;
import org.apache.cxf.service.model.BindingInfo;
import org.apache.cxf.service.model.EndpointInfo;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.MemoryTokenStore;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.tokenstore.TokenStore;
import org.apache.cxf.ws.security.wss4j.saml.SAML2CallbackHandler;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.SAMLParms;
import org.apache.ws.security.validate.Credential;
import org.easymock.EasyMock;

import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for local validation of SAML Assertions in the STSTokenValidator, and for the caching of
 * tokens that were validated (and transformed) by the STS.
 */
public class STSTokenValidatorTest {

    private static Crypto signingCrypto;
    private static Crypto trustedCrypto;
    private static Crypto untrustedCrypto;

    @BeforeClass
    public static void init() throws Exception {
        WSSConfig.init();
        signingCrypto = CryptoFactory.getInstance("outsecurity.properties");
        // Contains the signing certificate
        trustedCrypto = CryptoFactory.getInstance("outsecurity.properties");
        // Only trusts an unrelated CA
        untrustedCrypto = CryptoFactory.getInstance("cxfca.properties");
    }

    @Test
    public void testTrustedSignedAssertion() throws Exception {
        STSTokenValidator validator = new STSTokenValidator();
        RequestData data = createRequestData(trustedCrypto);
        assertTrue(validator.isValidatedLocally(createCredential(true, data), data));
    }

    @Test
    public void testUntrustedSignedAssertion() throws Exception {
        STSTokenValidator validator = new STSTokenValidator();
        RequestData data = createRequestData(untrustedCrypto);
        assertFalse(validator.isValidatedLocally(createCredential(true, data), data));
    }

    /**
     * An unsigned Assertion must not be treated as validated locally because a previous
     * signed Assertion was trusted.
     */
    @Test
    public void testUnsignedAssertionAfterTrustedAssertion() throws Exception {
        STSTokenValidator validator = new STSTokenValidator();

        RequestData trustedData = createRequestData(trustedCrypto);
        assertTrue(validator.isValidatedLocally(createCredential(true, trustedData), trustedData));

        RequestData data = createRequestData(trustedCrypto);
        assertFalse(validator.isValidatedLocally(createCredential(false, data), data));
    }

    /**
     * An untrusted Assertion must never be treated as validated locally, even when a trusted
     * Assertion is validated concurrently by the same STSTokenValidator.
     */
    @Test
    public void testConcurrentTrustedAndUntrustedAssertions() throws Exception {
        final STSTokenValidator validator = new STSTokenValidator();
        final int iterations = 200;

        final RequestData trustedData = createRequestData(trustedCrypto);
        final Credential trustedCredential = createCredential(true, trustedData);
        final RequestData untrustedData = createRequestData(untrustedCrypto);
        final Credential untrustedCredential = createCredential(true, untrustedData);

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Callable<Boolean> trusted = new Callable<Boolean>() {
                public Boolean call() throws Exception {
                    boolean result = true;
                    for (int i = 0; i < iterations; i++) {
                        result &= validator.isValidatedLocally(trustedCredential, trustedData);
                    }
                    return result;
                }
            };
            Callable<Boolean> untrusted = new Callable<Boolean>() {
                public Boolean call() throws Exception {
                    boolean result = false;
                    for (int i = 0; i < iterations; i++) {
                        result |= validator.isValidatedLocally(untrustedCredential, untrustedData);
                    }
                    return result;
                }
            };

            Future<Boolean> trustedResult = executor.submit(trusted);
            Future<Boolean> untrustedResult = executor.submit(untrusted);

            assertTrue(trustedResult.get(60, TimeUnit.SECONDS));
            assertFalse(untrustedResult.get(60, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * A UsernameToken with the same hashCode as a UsernameToken that was previously validated by the
     * STS must not be able to retrieve the (cached) token that the STS issued for it.
     */
    @Test
    public void testCachedTokenNotReturnedForCollidingUsernameToken() throws Exception {
        STSTokenValidator validator = new STSTokenValidator(true);
        TokenStore tokenStore = new MemoryTokenStore();
        MockSTSClient stsClient = new MockSTSClient(createTransformedToken());

        UsernameToken validToken = createUsernameToken("Aa", "password");
        UsernameToken collidingToken = createUsernameToken("BB", "password");
        // The tokens are different, but have the same hashCode
        assertEquals(validToken.hashCode(), collidingToken.hashCode());

        Credential credential = new Credential();
        credential.setUsernametoken(validToken);
        validator.validateWithSTS(credential, createMessage(tokenStore, stsClient));
        assertNotNull(credential.getTransformedToken());
        assertEquals(1, stsClient.getCalls());

        // The same UsernameToken is retrieved from the cache
        stsClient.setValid(false);
        credential = new Credential();
        credential.setUsernametoken(createUsernameToken("Aa", "password"));
        validator.validateWithSTS(credential, createMessage(tokenStore, stsClient));
        assertNotNull(credential.getTransformedToken());
        assertEquals(1, stsClient.getCalls());

        // The colliding UsernameToken must be validated by the STS, which rejects it
        Credential collidingCredential = new Credential();
        collidingCredential.setUsernametoken(collidingToken);
        try {
            validator.validateWithSTS(collidingCredential, createMessage(tokenStore, stsClient));
            fail("Failure expected on a UsernameToken that was not validated by the STS");
        } catch (WSSecurityException ex) {
            // expected
        }
        assertNull(collidingCredential.getTransformedToken());
        assertEquals(2, stsClient.getCalls());
    }

    /**
     * A signed SAML Assertion with a SignatureValue that has the same hashCode as the SignatureValue
     * of an Assertion that was previously validated by the STS must not be able to retrieve the (cached)
     * token that the STS issued for it.
     */
    @Test
    public void testCachedTokenNotReturnedForCollidingAssertion() throws Exception {
        STSTokenValidator validator = new STSTokenValidator(true);
        TokenStore tokenStore = new MemoryTokenStore();
        MockSTSClient stsClient = new MockSTSClient(createTransformedToken());
        RequestData data = createRequestData(trustedCrypto);

        Credential credential = createCredential(true, data);
        byte[] signatureValue = credential.getAssertion().getSignatureValue();
        validator.validateWithSTS(credential, createMessage(tokenStore, stsClient));
        assertNotNull(credential.getTransformedToken());
        assertEquals(1, stsClient.getCalls());

        // The same Assertion is retrieved from the cache
        stsClient.setValid(false);
        Credential cachedCredential = new Credential();
        cachedCredential.setAssertion(
            new AssertionWrapper(credential.getAssertion().getElement())
        );
        validator.validateWithSTS(cachedCredential, createMessage(tokenStore, stsClient));
        assertNotNull(cachedCredential.getTransformedToken());
        assertEquals(1, stsClient.getCalls());

        // Create another Assertion, with a SignatureValue that has the same hashCode as the cached one
        Credential otherCredential = createCredential(true, data);
        Element otherElement = otherCredential.getAssertion().getElement();
        Element signatureValueElement =
            (Element)otherElement.getElementsByTagNameNS(WSConstants.SIG_NS, "SignatureValue").item(0);
        byte[] collidingSignatureValue = createCollidingValue(signatureValue);
        signatureValueElement.setTextContent(Base64Utility.encode(collidingSignatureValue));
        AssertionWrapper collidingAssertion = new AssertionWrapper(otherElement);
        assertEquals(Arrays.hashCode(signatureValue),
                     Arrays.hashCode(collidingAssertion.getSignatureValue()));

        Credential collidingCredential = new Credential();
        collidingCredential.setAssertion(collidingAssertion);
        try {
            validator.validateWithSTS(collidingCredential, createMessage(tokenStore, stsClient));
            fail("Failure expected on an Assertion that was not validated by the STS");
        } catch (WSSecurityException ex) {
            // expected
        }
        assertNull(collidingCredential.getTransformedToken());
        assertEquals(2, stsClient.getCalls());
    }

    private static RequestData createRequestData(Crypto sigVerCrypto) {
        RequestData data = new RequestData();
        data.setSigCrypto(sigVerCrypto);
        data.setWssConfig(WSSConfig.getNewInstance());
        return data;
    }

    private static Credential createCredential(boolean signed, RequestData data) throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(callbackHandler);
        samlParms.setIssuer("www.example.com");
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        if (signed) {
            assertion.signAssertion("myalias", "myAliasPassword", signingCrypto, false);
        }

        // Round-trip the Assertion via DOM, as would happen on receipt of a message
        Document doc = DOMUtils.createDocument();
        Element element = assertion.toDOM(doc);
        // The Assertion must be attached to the Document so that the signature Reference can be resolved
        doc.appendChild(element);
        AssertionWrapper receivedAssertion = new AssertionWrapper(element);
        if (signed) {
            receivedAssertion.verifySignature(data, new WSDocInfo(doc));
        }

        Credential credential = new Credential();
        credential.setAssertion(receivedAssertion);
        return credential;
    }

    private static Element createTransformedToken() throws Exception {
        SAMLParms samlParms = new SAMLParms();
        samlParms.setCallbackHandler(new SAML2CallbackHandler());
        samlParms.setIssuer("sts");
        AssertionWrapper assertion = new AssertionWrapper(samlParms);
        Document doc = DOMUtils.createDocument();
        Element element = assertion.toDOM(doc);
        doc.appendChild(element);
        return element;
    }

    private static UsernameToken createUsernameToken(String name, String password) {
        Document doc = DOMUtils.createDocument();
        UsernameToken usernameToken = new UsernameToken(true, doc, WSConstants.PASSWORD_TEXT);
        usernameToken.setName(name);
        usernameToken.setPassword(password);
        return usernameToken;
    }

    /**
     * Create a different byte array that has the same Arrays.hashCode as the given one
     */
    private static byte[] createCollidingValue(byte[] value) {
        byte[] collidingValue = value.clone();
        for (int i = 0; i < collidingValue.length - 1; i++) {
            if (collidingValue[i] < Byte.MAX_VALUE && collidingValue[i + 1] >= Byte.MIN_VALUE + 31) {
                collidingValue[i] += 1;
                collidingValue[i + 1] -= 31;
                return collidingValue;
            }
        }
        throw new IllegalStateException("Can't create a colliding value");
    }

    private static Message createMessage(TokenStore tokenStore, STSClient stsClient) {
        EndpointInfo endpointInfo = new EndpointInfo();
        endpointInfo.setBinding(new BindingInfo(null, null));
        Endpoint endpoint = EasyMock.createNiceMock(Endpoint.class);
        EasyMock.expect(endpoint.getEndpointInfo()).andReturn(endpointInfo).anyTimes();
        EasyMock.replay(endpoint);

        Exchange exchange = new ExchangeImpl();
        exchange.put(Endpoint.class, endpoint);
        Message message = new MessageImpl();
        message.setExchange(exchange);
        message.put(SecurityConstants.TOKEN_STORE_CACHE_INSTANCE, tokenStore);
        message.put(SecurityConstants.STS_CLIENT, stsClient);
        return message;
    }

    /**
     * A mock STSClient, which returns a (transformed) token for a valid token, and otherwise throws
     * an exception.
     */
    private static final class MockSTSClient extends STSClient {
        private final Element transformedToken;
        private boolean valid = true;
        private int calls;

        MockSTSClient(Element transformedToken) {
            super(null);
            this.transformedToken = transformedToken;
        }

        @Override
        public List<SecurityToken> validateSecurityToken(SecurityToken tok) throws Exception {
            calls++;
            if (!valid) {
                throw new Exception("The token was rejected by the STS");
            }
            SecurityToken returnedToken = new SecurityToken("transformed-" + calls);
            returnedToken.setToken(transformedToken);
            return Collections.singletonList(returnedToken);
        }

        void setValid(boolean valid) {
            this.valid = valid;
        }

        int getCalls() {
            return calls;
        }
    }
}
