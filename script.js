/* Algorithm To Follow:
    1. Convert the given string to bytes using utf8ToBytes()
    2. Hash the bytes string using sha256().

    Note: The hashed string obtained is a Uint8Array. You might need to convert it into favourable type (Hex in this case).

    Requirements: 
    - npm install ethereum-cryptography

*/

// Libraries required for encryption
const { sha256 } = require("ethereum-cryptography/sha256");
const { toHex, utf8ToBytes } = require("ethereum-cryptography/utils");

const getText = () => {
    return document.getElementById("message-text-area").value;
}

const hash = (message) => {
    const messageBytes = utf8ToBytes(message);
    const messageHash = sha256(messageBytes);
    return toHex(messageHash);
}

const displayHash = () => {
    const hashedMessage = hash(getText());
    const displayArea = document.getElementById('encrypted-text-display-box');
    displayArea.innerHTML = hashedMessage;
}

const encryptButton = document.getElementById('encrypt-button');

encryptButton.addEventListener('click', displayHash);
