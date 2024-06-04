package com.adoptionapp.aws;

import com.adoptionapp.aws.service.CognitoUserService;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import software.amazon.awssdk.awscore.exception.AwsServiceException;

import java.util.HashMap;
import java.util.Map;

public class GetUserHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final CognitoUserService cognitoUserService;

    public GetUserHandler() {
        this.cognitoUserService = new CognitoUserService(System.getenv("AWS_REGION"));
    }

    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent().withHeaders(headers);
        Map<String, String> requestHeaders = input.getHeaders();
        LambdaLogger logger = context.getLogger();

        try {
            String authorization = requestHeaders.get("AccessToken");
            if (authorization == null || authorization.isEmpty()) {
                throw new IllegalArgumentException("Missing Authorization header");
            }

            JsonObject userDetails = cognitoUserService.getUser(authorization);
            response.withBody(new Gson().toJson(userDetails, JsonObject.class));
            response.withStatusCode(200);
        } catch (AwsServiceException ex) {
            logger.log("AWS Service Exception: " + ex.awsErrorDetails().errorMessage());
            ErrorResponse errorResponse = new ErrorResponse(ex.awsErrorDetails().errorMessage());
            String errorResponseJsonString = new Gson().toJson(errorResponse, ErrorResponse.class);
            response.withBody(errorResponseJsonString);
            response.withStatusCode(ex.awsErrorDetails().sdkHttpResponse().statusCode());
        } catch (IllegalArgumentException ex) {
            logger.log("Client Error: " + ex.getMessage());
            ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
            String errorResponseJsonString = new Gson().toJson(errorResponse, ErrorResponse.class);
            response.withBody(errorResponseJsonString);
            response.withStatusCode(400);
        } catch (Exception ex) {
            logger.log("Server Error: " + ex.getMessage());
            ErrorResponse errorResponse = new ErrorResponse(ex.getMessage());
            String errorResponseJsonString = new GsonBuilder().serializeNulls().create().toJson(errorResponse, ErrorResponse.class);
            response.withBody(errorResponseJsonString);
            response.withStatusCode(500);
        }

        return response;
    }

}
