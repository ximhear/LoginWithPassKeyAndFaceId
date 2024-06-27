const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const base64url = require('base64url');

const app = express();

const port = 3000;
app.use(bodyParser.json());

// .well-known 디렉토리의 정적 파일 제공 설정
app.use('/.well-known', express.static(path.join(__dirname, '.well-known')));

const SECRET_KEY = 'your-secret-key';
const users = {
    'user1': {
        password: 'password1',
        pin: '1234',
        refreshToken: null,
        passkey: null // PassKey 데이터를 저장하기 위한 필드
    }
};

const generateAccessToken = (username) => {
    console.log(`Generating access token for ${username}`);
    return jwt.sign({ username }, SECRET_KEY, { expiresIn: '15m' });
};

const generateRefreshToken = (username) => {
    console.log(`Generating refresh token for ${username}`);
    const refreshToken = jwt.sign({ username }, SECRET_KEY, { expiresIn: '7d' });
    users[username].refreshToken = refreshToken;
    return refreshToken;
};

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    console.log(`Login attempt for username: ${username}`);

    const user = users[username];

    if (!user || user.password !== password) {
        console.log(`Invalid credentials for username: ${username}`);
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const accessToken = generateAccessToken(username);
    const refreshToken = generateRefreshToken(username);

    console.log(`Login successful for username: ${username}`);
    res.json({
        accessToken,
        refreshToken
    });
});

app.post('/register-passkey', (req, res) => {
    const { userID, rawID, attestationObject, clientDataJSON } = req.body;
    console.log(`PassKey registration for userID: ${userID}`);

    // PassKey 데이터를 저장
    if (!users[userID]) {
        users[userID] = {};
    }
    users[userID].passkey = { rawID, attestationObject, clientDataJSON };

    console.log(`PassKey data saved for userID: ${userID}`);
    res.status(200).send('PassKey registration successful');
});

app.post('/authenticate-passkey', (req, res) => {
    const { userID, rawID, authenticatorData, clientDataJSON, signature } = req.body;
    console.log(`PassKey authentication attempt for userID: ${userID}`);

    const user = users[userID];
    if (!user || !user.passkey) {
        console.log(`No PassKey registered for userID: ${userID}`);
        return res.status(401).json({ message: 'No PassKey registered for this user' });
    }

    // PassKey 인증 검증 로직 (예: rawID 비교, 서명 검증 등)
    const expectedRawID = user.passkey.rawID;
    if (rawID !== expectedRawID) {
        console.log(`Invalid PassKey rawID for userID: ${userID}`);
        return res.status(401).json({ message: 'Invalid PassKey' });
    }

    // 실제로 서명을 검증하는 로직을 추가해야 합니다. 여기는 간단히 비교만 수행합니다.

    console.log(`PassKey authentication successful for userID: ${userID}`);
    const accessToken = generateAccessToken(userID);
    const refreshToken = generateRefreshToken(userID);

    res.json({
        accessToken,
        refreshToken
    });
});

app.post('/authenticateWithPin', (req, res) => {
    const { pin } = req.body;
    const username = 'user1'; // You should get the username from the client's stored information
    console.log(`PIN authentication attempt for username: ${username}`);

    if (users[username].pin !== pin) {
        console.log(`Invalid PIN for username: ${username}`);
        return res.status(401).json({ message: 'Invalid PIN' });
    }

    const accessToken = generateAccessToken(username);
    const refreshToken = generateRefreshToken(username);

    console.log(`PIN authentication successful for username: ${username}`);
    res.json({
        accessToken,
        refreshToken
    });
});

app.post('/refresh', (req, res) => {
    const { refreshToken } = req.body;
    console.log(`Token refresh attempt with refreshToken: ${refreshToken}`);

    if (!refreshToken) {
        console.log(`Refresh token not provided`);
        return res.status(401).json({ message: 'Refresh token required' });
    }

    jwt.verify(refreshToken, SECRET_KEY, (err, user) => {
        if (err) {
            console.log(`Token verification error: ${err.message}`);
            return res.status(403).json({ message: 'Invalid refresh token' });
        }
        
        if (users[user.username].refreshToken !== refreshToken) {
            console.log(`Refresh token mismatch for username: ${user.username}`);
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

        const accessToken = generateAccessToken(user.username);
        const newRefreshToken = generateRefreshToken(user.username);

        console.log(`Token refresh successful for username: ${user.username}`);
        res.json({
            accessToken,
            refreshToken: newRefreshToken
        });
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});