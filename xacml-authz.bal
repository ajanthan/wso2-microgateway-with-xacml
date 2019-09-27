import ballerina/io;
import ballerina/http;
import ballerina/runtime;
import ballerina/mime;
import ballerina/internal;

http:Client pdpEndpoint = new(
                              "https://localhost:9443",
                              config = {
                                  secureSocket: {
                                      trustStore: {
                                          path: "${ballerina.home}/bre/security/ballerinaTruststore.p12",
                                          password: "ballerina"
                                      }
                                  }
                              }
);

function authz(string user, string res, string action) returns boolean|error {
    http:Request xacmlReq = new;
    json authzReq = getAuthzRequest(res, action, user);
    io:println(authzReq.toString());

    xacmlReq.setJsonPayload(authzReq, contentType = "application/json");
    xacmlReq.addHeader("Authorization", "Basic YWRtaW46YWRtaW4=");
    http:Response|error response = pdpEndpoint->post("/api/identity/entitlement/decision/pdp", xacmlReq);
    if (response is http:Response){
    io:println(response);
    json jsonResp = check response.getJsonPayload();
    json result = jsonResp.Response[0];
    json allow = result.Decision;
    io:println(allow.toString());
    if (allow != null && allow.toString().equalsIgnoreCase("permit")) {
        return true;
    } else {
        io:println(jsonResp.toString());
        return false;
    }
    } else if (response is error){
    io:println(response);
    return false;
    }
    return false;
}

public function validateRequest (http:Caller outboundEp, http:Request req) {
     string path = req.rawPath;
     string method = req.method;
     string jwtToken = runtime:getInvocationContext().authContext.authToken;
     string|error username = decode(jwtToken);
     io:println("Request is intercepted.");
     io:println("Path: " + path);
     io:println("Method: " + method);
     if (username is string) {
     io:println("Subject: " + username);
     boolean|error allow = authz(username, path, method);
     if (allow is boolean){
     if (allow){
        io:println("Policy validation is sucessfull");
        return;
    }

    http:Response res = new;
    json message = { "status": "user not authorized" };
    res.statusCode = 401;
    res.setPayload(message);
    _ = outboundEp->respond(res);
    } else if (allow is error){
    io:println(allow);
    http:Response res = new;
    json message = { "status": "user not authorized" };
    res.statusCode = 401;
    res.setPayload(message);
    _ = outboundEp->respond(res);
    }
    } else if (username is error){
    io:println(username);
    }

}

function getAuthzRequest(string res, string method, string subject) returns @untainted json {
    return { "Request": {
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


function decode(string rawJWT) returns string|error {
    string username = "";
    string[] split_string = rawJWT.split("\\.");
    string base64EncodedBody = split_string[1];
    string|error decodedVal = mime:base64DecodeString(base64EncodedBody, charset = "utf-8");
    if (decodedVal is string){
    json|error payload = internal:parseJson(decodedVal);
    if (payload is json){
    username = payload["sub"].toString();
    } else if (payload is error){
    return payload;
    }
    } else if (decodedVal is error){
    return decodedVal;
    }
    return username;
}