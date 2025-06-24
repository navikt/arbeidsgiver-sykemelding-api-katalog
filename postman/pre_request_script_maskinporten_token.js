// Dette scriptet kommer fra "API - Beskrivelser og eksempler" i https://github.com/navikt/sykepenger-im-lps-api/wiki
const jsonwebtoken = pm.require('npm:jsonwebtoken@8.5.1');
const { v4: uuidv4 } = require('uuid');

const privateKey = pm.environment.get("MASKINPORTEN_PRIVATE_KEY");
const clientId = pm.environment.get("MASKINPORTEN_CLIENT_ID"); // Integration ID
const kid = pm.environment.get("MASKINPORTEN_KID");
const orgnr = pm.environment.get("customerOrgnr")

if (!privateKey || !clientId || !kid || !orgnr) {
  throw new Error("Fetching maskinporten token failed. Missing required environment variables: customerOrgnr, MASKINPORTEN_PRIVATE_KEY, MASKINPORTEN_CLIENT_ID, or MASKINPORTEN_KID");
}

const privateKeySpaces = privateKey.split(" ").length - 1
if(privateKeySpaces !== 4) {
    throw new Error(
        "MASKINPORTEN_PRIVATE_KEY has " + privateKeySpaces + " space \" \" characters when it should only have 4 (can occur when pasting key in field that does not support newlines)"
    );
}

async function main() {
    const jwt = generateJWT(orgnr)
    const maskinportenToken = await getMaskinportenToken(jwt)
    
    pm.environment.set("bearerToken", maskinportenToken)
    console.log("Set Maskinporten bearerToken for systemuser with permissions for orgnr: " + orgnr)
}

// Generer JWT for systembruker ref: https://docs.digdir.no/docs/Maskinporten/maskinporten_func_systembruker.html#foresp%C3%B8rsel
function generateJWT(orgnr) {
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const payload = {
        aud: "https://test.maskinporten.no/",
        iss: clientId,
        scope: "nav:helseytelser/sykepenger",
        authorization_details: [{
            type: "urn:altinn:systemuser",
            systemuser_org: {
                authority: "iso6523-actorid-upis",
                ID: "0192:" + orgnr
            }
        }],
        iat: currentTimestamp,
        exp: currentTimestamp + 120,
        jti: uuidv4()
    };
    const options = {
        algorithm: 'RS256',
        header: {
            kid: kid
        }
    };

    return jsonwebtoken.sign(payload, privateKey, options);
}

// Hent token med JWT ref: https://docs.digdir.no/docs/Maskinporten/maskinporten_protocol_token.html
async function getMaskinportenToken(assertion) {
  const res = await new Promise(r =>
    pm.sendRequest({
      url: 'https://test.maskinporten.no/token',
      method: 'POST',
      header: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: {
        mode: 'urlencoded',
        urlencoded: [
          { key: 'grant_type', value: 'urn:ietf:params:oauth:grant-type:jwt-bearer' },
          { key: 'assertion', value: assertion }
        ]
      }
    }, (_, res) => r(res))
  );
    
  if (res.code !== 200) throw new Error('Maskinporten token request failed: ' + res.code + "\n" + res.body);
  return res.json().access_token;
}

main()
