# eid-dca-verifier

Proof of concept verifier for the [Digital Credential API](https://github.com/w3c-fedid/digital-credentials) accepting Estonian ID card self-signed authentication credential in [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) format. 
To generate and present the authentication credential, use the [eid-dca](https://github.com/aarmam/eid-dca) wallet.

## Requirements

- Chrome 128 or later
- Enable the flag at chrome://flags#web-identity-digital-credentials

Read more about the [Digital Credentials API origin trial](https://developer.chrome.com/blog/digital-credentials-api-origin-trial)

## Running in Docker

Build docker image locally

```shell
./mvnw spring-boot:build-image
```

or inside Docker

Windows Powershell
```shell
docker run --pull always --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${env:USERPROFILE}\.m2:/root/.m2" -v "${PWD}:/usr/src/project" -w /usr/src/project maven:3.9-eclipse-temurin-21 mvn spring-boot:build-image -DskipTests
```

Linux
```shell
docker run --pull always --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$HOME/.m2:/root/.m2" -v "$PWD:/usr/src/project" -w /usr/src/project maven:3.9-eclipse-temurin-21 mvn spring-boot:build-image -DskipTests
```

Run the verifier service

```shell
docker compose up
```

Test the authentication flow

https://eid-dca-verifier.localhost:8443

## Credential generation flow

```mermaid
sequenceDiagram
    box Mobile phone
        actor U as user
        participant W as Wallet <br/>(eid-dca)
        participant ID as Estonian ID card
        participant A as Android
    end
    U ->> W: Create Authentication Credential
    activate W
    W ->>+ U: Request ID card CAN number
    U -->>- W: CAN number
    W ->>+ U: Request consent by taping ID card to NFC reader and input of PIN2
    U -->>- W: Tap ID card and confirm with PIN2
    W ->> A: Start NFC discovery
    activate A
    W ->> ID: Setup PACE tunnel using CAN number
    activate ID
    W ->>+ ID: Get ID card authentication/signature certificates
    ID -->>- W: Certificates
    W ->> W: Generate the Device Key Info (ISO/IEC 18013-5) <br/>using the ID card authentication certificate public key.
    W ->> W: Generate the Mobile Security Object (ISO/IEC 18013-5) <br/> using the signing certificate as issuer certificate <br/> and Device Key Info as the binding key. 
    W ->> W: Get SHA-384 hash of the Mobile Security Object
    W ->>+ ID: Sign the hash with the ID card signature certificate (PIN2)
    ID -->>- W: Signature
    deactivate ID
    A --> W: End NFC session
    deactivate A    
    W ->> W: Add signature to the Mobile Security Object
    W ->> W: Add the Mobile Security Object <br/>to the new Authentication Credential (mdoc)
    W ->>+ A: Register the Authentication Credential metadata <br/>and the WASM credential matcher<br/>to the Credential Manager API
    A -->>- W: Success
    W ->>+ A: Store the Authentication Credential (mdoc) <br/>to the secure-storage
    A -->>- W: Success
    W -->> U: Show success message
    deactivate W
```

## Authentication flow

```mermaid
sequenceDiagram
    box Mobile phone
        actor U as user
        participant B as Chrome browser
        participant V as Verifier <br/>(eid-dca-verifier)
        participant A as Android
        participant ID as Estonian ID card
        participant W as Wallet <br/>(eid-dca)
    end
    U ->> B: Login
    activate B
    B ->>+ V: Request nonce (POST /login/vp/nonce)
    V ->> V: Create session
    V ->> V: Generate and store nonce
    V -->>- B: Return nonce, set cookie
    B ->> B: Generate OpenID4VP request including the nonce
    activate B
    B ->> B: navigator.credentials.get() (DC API)
    B ->> A: Request credential
    activate A
    A ->> A: Credential Manager API matches the <br/>requested credential using the WASM matcher
    A ->>+ U: Show the matched credential metadata <br/>and ask for consent
    U -->>- A: Confirm consent
    A ->> W: Credential Manager API start the get credential activity <br/> (androidx.credentials.registry.provider.action.GET_CREDENTIAL)
    activate W
    W ->> W: Parse the request <br/>and extract the document request, nonce, origin 
    W ->>+ U: Show origin and ask for consent <br/>by taping ID card to NFC reader and input of PIN1
    U ->>- W: Tap ID card and confirm with PIN1
    W ->>+ A: Get Authentication Credential (mdoc) <br/>and CAN number from secure-storage
    A -->>- W: Credential
    W ->> W: Generate the  <br/>OpenID4VPDCAPIHandover (ISO/IEC 18013-5) <br/> which includes the nonce and origin.
    W ->> W: Generate the Device Authentication <br/>(ISO/IEC 18013-5) using the handover.
    W ->> W: Get SHA-384 hash of the Device Authentication
     W ->> A: Start NFC discovery
    activate A
    W ->> ID: Setup PACE tunnel using CAN number
    activate ID
    W ->>+ ID: Sign the hash with the ID <br/> card authentication certificate (PIN1)
    ID -->>- W: Signature
    deactivate ID
    A --> W: End NFC session
    deactivate A   
    W ->> W: Add the signature to the Device Signature (ISO/IEC 18013-5) <br/> with detached payload (Device Authentication)
    W ->> W: Add the Device Authentication <br/>to Authentication Credential (mdoc)
    W ->> W: Generate the Verifiable Presentation token (vp_token) <br/> which includes the Authentication Credential. 
    W -->> A: Return the vp_token <br/>to the Credential Manager API
    deactivate W
    A -->> B: Return the vp_token
    deactivate B
    deactivate A
    B ->>+ V: Send the vp_token <br/>(POST /login/vp)
    V ->> V: Get nonce from the session
    V ->> V: Get Estonia root CA certificate
    V ->> V: Reconstruct the OpenID4VPDCAPIHandover using the nonce and origin
    V ->> V: Validate the Authentication Credential <br/>from the vp_token using the OpenID4VPDCAPIHandover <br/>and CA certificate
    alt Validation successful
        V -->> B: Redirect to redirect_uri
    else Validation failed
        V -->> B: Show error message
    end
    deactivate B
```