# spring-auth-server

PKCE javascript example

```
function generateCodeVerifier() {
    var returnValue = "";
    var randomByteArray = new Unit8Array(32);
    window.crypto.getRandomValues(randomByteArray);
    
    returnValue = base64urlencode(randomByteArray);
    return returnValue;
}

async function generateCodeChallenge(codeVerifier) {
    var condeChallengeValue = "";
    
    var textEncoder = new TextEncoder('US-ASCII');
    var encodedValue = textEncoder.encode(codeVerifier);
    var digest = await window.crypto.subtle.digest('SHA-256', encodedValue);
    
    condeChallengeValue = base64urlencode(Array.from(new Unit8Array(digest)));
    
    return condeChallengeValue;
}

function base64urlencode(sourceValue) {
    var strValue = String.fromCharCode.apply(null, sourceValue);
    var base64encoded = btoa(strValue);
    var base64urlEncoded = base64encoded.replace(/\+/g, '-').replace(/\//g, '').replace(/=/g, '');
    return base64urlEncoded
}
```