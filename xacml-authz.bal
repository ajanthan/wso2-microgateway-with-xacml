import ballerina/auth;
import ballerina/config;
import ballerina/http;
import ballerina/jwt;
import ballerina/log;
import ballerina/runtime;


auth:OutboundBasicAuthProvider basicAuthProvider = new ({
    username: config:getAsString("pbac.pdp.username", "admin"),
    password: config:getAsString("pbac.pdp.password", "admin")
});
http:BasicAuthHandler outboundBasicAuthHandler = new (basicAuthProvider);
http:Client pdpEndpoint = new (
config:getAsString("pbac.pdp.url", "https://localhost:9443"), {
    auth: {authHandler: outboundBasicAuthHandler
    },
    secureSocket: {
        trustStore: {
            path: "${ballerina.home}/bre/security/ballerinaTruststore.p12",
            password: "ballerina"
        }
    }

}
);

function authz(string user, string res, string action) returns boolean | error {
    http:Request xacmlReq = new;
    json authzReq = getAuthzRequest(res, action, user);
    log:printDebug("XACML request: " + authzReq.toJsonString());
    xacmlReq.setJsonPayload(authzReq, contentType = "application/json");
    var response = pdpEndpoint->post("/api/identity/entitlement/decision/pdp", xacmlReq);
    if (response is http:Response) {
        var jsonResp = response.getJsonPayload();
        if (jsonResp is json) {
            log:printDebug("Received response: " + jsonResp.toString());
            json[] resp = <json[]>jsonResp.Response;
            json result = <json>resp[0];
            json decison = <json>result.Decision;
            if (decison != null && decison.toString() == "Permit") {
                log:printDebug("Access is permitted");
                return true;
            } else {
                log:printDebug("Access is denied");
                return false;
            }
        } else {
            log:printError(jsonResp.toString());
            return false;
        }
    }
    return false;
}

public function validateRequest(http:Caller outboundEp, http:Request req) {
    string path = req.rawPath;
    string method = req.method;
    string? username = "";
    runtime:InvocationContext invocationContext = runtime:getInvocationContext();
    runtime:AuthenticationContext? authContext = invocationContext?.authenticationContext;
    if (authContext is runtime:AuthenticationContext) {
        string? jwtToken = authContext?.authToken;
        if (jwtToken is string) {
            [jwt:JwtHeader, jwt:JwtPayload] | jwt:Error[header, payload] = jwt:decodeJwt(jwtToken);
            username = payload["sub"];
            if (username is string) {
                log:printDebug("Subject in the context " + username);
                var allow = authz(username, path, method);
                if (allow is boolean) {
                    if (allow) {
                        return;
                    }
                    http:Response res = new;
                    json message = {"status": "user not authorized"};
                    res.statusCode = 403;
                    res.setPayload(message);
                    var result = outboundEp->respond(res);
                    if (result is error) {
                        return;
                    }
                } else {
                    log:printError("Error in pdp: " + allow.toString());
                    http:Response res = new;
                    json message = {"status": "user not authorized"};
                    res.statusCode = 403;
                    res.setPayload(message);
                    var result = outboundEp->respond(res);
                    if (result is error) {
                        return;
                    }
                }
            } else {
                log:printError("Username is not set in the context");
            }

        }
    }
}

function getAuthzRequest(string res, string method, string subject) returns @untainted json {
    return {
        "Request": {
            "Action": {
                "Attribute": [
                {
                    "AttributeId": "urn:oasis:names:tc:xacml:1.0:action:action-id",
                    "Value": method
                }
                ]
            },
            "Resource": {
                "Attribute": [
                {
                    "AttributeId": "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
                    "Value": res
                }
                ]
            },
            "AccessSubject": {
                "Attribute": [
                {
                    "AttributeId": "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
                    "Value": subject
                }
                ]
            }
        }
    };
}
