package com.github.aarmam.eid.dca.verifier.security;

import com.upokecenter.cbor.CBORObject;
import eu.webeid.security.certificate.CertificateData;
import id.walt.mdoc.COSECryptoProviderKeyInfo;
import id.walt.mdoc.SimpleCOSECryptoProvider;
import id.walt.mdoc.cose.COSESign1;
import id.walt.mdoc.dataelement.*;
import id.walt.mdoc.dataretrieval.DeviceResponse;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.doc.MDocVerificationParams;
import id.walt.mdoc.doc.VerificationType;
import id.walt.mdoc.mdocauth.DeviceAuthentication;
import id.walt.mdoc.mso.DeviceKeyInfo;
import id.walt.mdoc.mso.MSO;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.cose.java.AlgorithmID;
import org.cose.java.CoseException;
import org.cose.java.OneKey;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static java.util.Objects.requireNonNull;

@Slf4j
@RequiredArgsConstructor
public class VpTokenValidator {
    private static final String DOC_TYPE = "eu.europa.ec.eudi.eid.1";
    private static final String KEY_ID_ISSUER = "issuer-key-id";
    private static final String KEY_ID_DEVICE = "device-key-id";
    private static final String OPENID_HANDOVER_TYPE = "OpenID4VPDCAPIHandover";
    private static final Map<Integer, AlgorithmID> EC_ALGORITHM_MAP = Map.of(
            256, AlgorithmID.ECDSA_256,
            384, AlgorithmID.ECDSA_384,
            521, AlgorithmID.ECDSA_512
    );
    private final List<X509Certificate> trustedRootCAs;
    private final String expectedOrigin;

    public VpUserEntity validate(Object vpToken, String challengeNonce) {
        if (vpToken instanceof String token) {
            try {
                DeviceResponse deviceResponse = DeviceResponse.Companion.fromCBORBase64URL(token);
                MDoc mDoc = deviceResponse.getDocuments().getFirst();
                COSESign1 issuerSignature = requireNonNull(mDoc.getIssuerSigned()).getIssuerAuth();
                List<X509Certificate> issuerCertificateChain = parseX509CertificateChain(requireNonNull(issuerSignature).getX5Chain());
                COSESign1 deviceSignature = requireNonNull(mDoc.getDeviceSigned()).getDeviceAuth().getDeviceSignature();
                MDocVerificationParams verificationParams = getVerificationParams(challengeNonce);
                SimpleCOSECryptoProvider validationCryptoProvider = new SimpleCOSECryptoProvider(List.of(getIssuerKeyInfo(issuerCertificateChain, trustedRootCAs), getDeviceKeyInfo(mDoc)));

                if (!mDoc.verify(verificationParams, validationCryptoProvider)) {
                    log.debug("Invalid mDoc verification: {}", mDoc.getErrors());
                    throw new BadCredentialsException("Invalid credential.");
                }

                return getUserEntity(deviceSignature, issuerCertificateChain);
            } catch (Exception e) {
                throw new BadCredentialsException("Invalid credential.", e);
            }
        } else {
            throw new BadCredentialsException("Invalid vpToken format. Expected VpToken with base64 URL encoded string.");
        }
    }

    private List<X509Certificate> parseX509CertificateChain(byte[] x5c) throws CertificateException {
        return CertificateFactory.getInstance("X509")
                .generateCertificates(new ByteArrayInputStream(requireNonNull(x5c)))
                .stream()
                .filter(cert -> cert instanceof X509Certificate)
                .map(cert -> (X509Certificate) cert)
                .toList();
    }

    private MDocVerificationParams getVerificationParams(String challengeNonce) {
        return new MDocVerificationParams(
                VerificationType.Companion.getAll(),
                KEY_ID_ISSUER,
                KEY_ID_DEVICE,
                null,
                getDeviceAuthentication(challengeNonce),
                null
        );
    }

    @SneakyThrows
    public DeviceAuthentication getDeviceAuthentication(String challengeNonce) {
        ListElement handover = new ListElement(List.of(new StringElement(expectedOrigin), new StringElement(challengeNonce), new NullElement()));
        byte[] handoverHash = MessageDigest.getInstance("SHA-256").digest(handover.toCBOR());
        ListElement sessionTranscript = new ListElement(
                List.of(
                        new NullElement(),
                        new NullElement(),
                        new ListElement(List.of(
                                new StringElement(OPENID_HANDOVER_TYPE),
                                new ByteStringElement(handoverHash)
                        ))));
        EncodedCBORElement deviceNameSpaces = new EncodedCBORElement(new MapElement(Map.of()));
        return new DeviceAuthentication(sessionTranscript, DOC_TYPE, deviceNameSpaces);
    }

    public COSECryptoProviderKeyInfo getIssuerKeyInfo(List<X509Certificate> issuerCertificateChain, List<X509Certificate> trustedRootCAs) {
        X509Certificate issuerCert = issuerCertificateChain.getFirst();
        PublicKey issuerPublicKey = issuerCert.getPublicKey();
        return new COSECryptoProviderKeyInfo(KEY_ID_ISSUER, getAlgorithmId(issuerPublicKey), issuerPublicKey, null, issuerCertificateChain, trustedRootCAs);
    }

    public COSECryptoProviderKeyInfo getDeviceKeyInfo(MDoc mDoc) {
        PublicKey devicePublicKey = getDevicePublicKey(mDoc);
        return new COSECryptoProviderKeyInfo(KEY_ID_DEVICE, getAlgorithmId(devicePublicKey), devicePublicKey, null, emptyList(), emptyList());
    }

    public AlgorithmID getAlgorithmId(PublicKey publicKey) {
        if (publicKey instanceof ECPublicKey ecPublicKey) {
            int bitLength = ecPublicKey.getParams().getOrder().bitLength();
            return EC_ALGORITHM_MAP.get(bitLength);
        } else {
            throw new IllegalArgumentException("Invalid key type. An Elliptic Curve key is required by ISO/IEC 18013-5:2021.");
        }
    }

    private PublicKey getDevicePublicKey(MDoc mDoc) {
        MSO mso = requireNonNull(mDoc.getMSO());
        DeviceKeyInfo deviceKeyInfo = mso.getDeviceKeyInfo();
        MapElement deviceKey = deviceKeyInfo.getDeviceKey();
        try {
            return new OneKey(CBORObject.DecodeFromBytes(deviceKey.toCBOR())).AsPublicKey();
        } catch (CoseException e) {
            throw new BadCredentialsException("Invalid device key.", e);
        }
    }

    private VpUserEntity getUserEntity(COSESign1 deviceSignature, List<X509Certificate> issuerCertificateChain) throws CertificateException {
        X509Certificate deviceCertificate = getDeviceX509Certificate(deviceSignature);
        final String principalName = getPrincipalNameFromCertificate(deviceCertificate);
        final String idCode = CertificateData.getSubjectIdCode(deviceCertificate);
        return VpUserEntity.builder()
                .name(principalName)
                .idCode(idCode)
                .authCertificate(deviceCertificate)
                .signCertificate(issuerCertificateChain.getFirst())
                .build();
    }

    private X509Certificate getDeviceX509Certificate(COSESign1 deviceSignature) throws CertificateException {
        List<X509Certificate> deviceCertificateChain = parseX509CertificateChain(requireNonNull(deviceSignature).getX5Chain());
        if (deviceCertificateChain.isEmpty()) {
            throw new BadCredentialsException("Invalid credential.");
        }
        return deviceCertificateChain.getFirst();
    }

    private String getPrincipalNameFromCertificate(X509Certificate userCertificate) {
        try {
            final String givenName = CertificateData.getSubjectGivenName(userCertificate);
            final String surname = CertificateData.getSubjectSurname(userCertificate);
            if (StringUtils.hasText(givenName) && StringUtils.hasText(surname)) {
                return givenName + ' ' + surname;
            } else {
                return CertificateData.getSubjectCN(userCertificate);
            }
        } catch (CertificateEncodingException e) {
            throw new BadCredentialsException("Certificate does not contain subject CN.", e);
        }
    }
}
