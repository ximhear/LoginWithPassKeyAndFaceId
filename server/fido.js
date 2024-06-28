const express = require('express');
const bodyParser = require('body-parser');
const { Fido2Lib } = require('fido2-lib');

const app = express();
app.use(bodyParser.json());

const fido2 = new Fido2Lib({
    timeout: 60000,
    rpId: "eng-rc-server.vercel.app",
    rpName: "My Service",
    challengeSize: 64,
    attestation: "direct",
    cryptoParams: [-7, -257],
});

let userDatabase = {}; // 임시 사용자 데이터베이스

app.post('/registerRequest', async (req, res) => {
    const userId = req.body.userId;
    const registrationOptions = await fido2.attestationOptions();
    registrationOptions.user = {
        id: Buffer.from(userId, 'utf-8'),
        name: userId,
        displayName: userId
    };
    console.log('userId:', userId);
    console.log(registrationOptions.user.id);
    registrationOptions.challenge = Buffer.from(registrationOptions.challenge).toString('base64');
    userDatabase[userId] = { ...userDatabase[userId], registrationOptions };
    console.log(JSON.stringify(registrationOptions, null, 2));
    res.json(registrationOptions);
});

app.post('/registerResponse', async (req, res) => {
    const { userId, response, id, rawId } = req.body;
    const { attestationObject, clientDataJSON } = response || {};
    const { registrationOptions } = userDatabase[userId];

    console.log('userId:', userId);
    console.log('attestationObject:', attestationObject);
    console.log('clientDataJSON:', clientDataJSON);
    console.log('registrationOptions:', registrationOptions);
    console.log('challenge:', registrationOptions.challenge);
    console.log('-------------------------------')

    try {
        if (!attestationObject || !clientDataJSON || !id || !rawId) {
            throw new Error('Missing required fields in the response.');
        }

        const options = { 
            ...registrationOptions,
            factor: 'either', // 추가된 부분
            origin: 'https://eng-rc-server.vercel.app'
        };
        console.log('options:', options);
        console.log('id:', id);
        console.log('rawId:', rawId);
    console.log('-------------------------------')

        const attestationResult = await fido2.attestationResult({
            rawId: Uint8Array.from(Buffer.from(rawId, 'base64')).buffer,
            response: {
                attestationObject: Uint8Array.from(Buffer.from(attestationObject, 'base64')).buffer,
                clientDataJSON: Uint8Array.from(Buffer.from(clientDataJSON, 'base64')).buffer
            }
        }, options);
        
        console.log('attestationResult:', attestationResult);

        userDatabase[userId].authenticator = attestationResult.authnrData;
        userDatabase[userId].publicKey = attestationResult.authnrData.credentialPublicKeyPem; // 공개 키 저장
        userDatabase[userId].prevCounter = attestationResult.authnrData.counter || 0; // counter가 null이면 0으로 설정
        userDatabase[userId].publicKey = attestationResult.authnrData.get('credentialPublicKeyPem'); // counter가 null이면 0으로 설정
        console.log('prevCounter', attestationResult.authnrData.counter);
        res.json({ status: 'ok' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/authRequest', async (req, res) => {
    const userId = req.body.userId;
    const authenticator = userDatabase[userId].authenticator;

    const assertionOptions = await fido2.assertionOptions();
    assertionOptions.challenge = Buffer.from(assertionOptions.challenge).toString('base64');
    assertionOptions.allowCredentials = [{
        type: 'public-key',
        id: authenticator.credId,
        transports: ['internal']
    }];
    userDatabase[userId].assertionOptions = assertionOptions;
    userDatabase[userId].prevCounter = authenticator.counter || 0; // prevCounter 값을 설정
    res.json(assertionOptions);
});

app.post('/authResponse', async (req, res) => {
    const { userId, response, id, rawId } = req.body;
    const { authenticatorData, clientDataJSON, signature } = response || {};
    const { assertionOptions, authenticator, prevCounter, publicKey } = userDatabase[userId];

    console.log('userDatabase:', userDatabase);
    console.log('authenticator:', authenticator);

    try {
        if (!authenticatorData || !clientDataJSON || !signature || !id || !rawId) {
            console.log('missing fields')
            throw new Error('Missing required fields in the response.');
        }
        
        console.log("prevCounter:", prevCounter);
        console.log('challenge:', assertionOptions.challenge);
        console.log('signature:', signature);
        // base64 to string
        const decodedString = atob(clientDataJSON);
        // UTF-8 문자열로 변환
        const utf8String = decodeURIComponent(escape(decodedString));
        console.log('clientDataJSON:', utf8String);
        console.log('prevCounter:', prevCounter);

        const assertionResult = await fido2.assertionResult({
            id: Uint8Array.from(Buffer.from(id, 'base64')).buffer,
            rawId: Uint8Array.from(Buffer.from(rawId, 'base64')).buffer,
            response: {
                authenticatorData: Uint8Array.from(Buffer.from(authenticatorData, 'base64')).buffer,
                clientDataJSON: Uint8Array.from(Buffer.from(clientDataJSON, 'base64')).buffer,
                signature: Uint8Array.from(Buffer.from(signature, 'base64')).buffer
            },
        }, {
            ...assertionOptions,
            factor: 'either', // 추가된 부분
            origin: 'https://eng-rc-server.vercel.app',
            prevCounter: prevCounter, // prevCounter를 assertionResult에 포함
            publicKey: publicKey, // 저장된 공개 키 사용
            userHandle: null,
            allowCredentials: null,
        });

        userDatabase[userId].prevCounter = assertionResult.authnrData.get('counter');
        console.log('counter:', assertionResult.authnrData.get('counter'));
        res.json({ status: 'ok', result: assertionResult });
    } catch (err) {
        console.error(err.message);
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
