const crypto = require('crypto');

/**
 * Check Twikey Webhook
 * @param {string} signature - X-Signature header
 * @param {string} apikey - Twikey apikey
 * @param {string} qs - Query String coming from Twikey
 */
const checkHmacValidity = (apikey,signature, qs) => {

    if (!qs || !signature) {
        throw "Invalid signature or missing api key";
    }
    let decodedQuerystring = decodeURIComponent(qs);

    let hash = crypto.createHmac('sha256', apikey).update(decodedQuerystring).digest('hex').toUpperCase();
    // validate and return
    return hash === signature
};

// var test = function(){
//     const querystring = /*http://my.company.com/webhook?*/ 'msg=dummytest&type=event';
//     const header_x_signature = '417745C0DE5DE5BFEAF.....'; // header coming from Twikey
//     const api_key = 'A03EB2.....'; // Api found in your Twikey dashboard
//     console.log("Valid ? ",checkHmacValidity(api_key,header_x_signature,querystring));
// }

module.exports = checkHmacValidity;
