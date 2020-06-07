package org.forrester.password.client;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

import static org.apache.commons.codec.Charsets.UTF_8;

public class App {

    private static final Logger log = Logger.getLogger(App.class);

    public static void main(String[] args) throws Exception {

        System.setProperty("javax.net.ssl.trustStore", "/home/nipun/data/repos/nipunthathsara/forrester-demo-passwords/src/main/resources/wso2carbon.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "wso2carbon");
        System.setProperty("javax.net.ssl.trustStoreType", "JKS");

        JSONArray usersArray = getAllUsers();
        StringBuilder stringBuilder = new StringBuilder();

        JSONObject user;
        for (Object userObject : usersArray) {
            if (userObject instanceof JSONObject) {
                user = (JSONObject) userObject;
            } else {
                log.error("Skipping entry as not an JSON Object");
                continue;
            }
            String username = user.get("userName").toString();
            String scimId = user.get("id").toString();
            log.info("Iterating username : " + username + " , id : " + scimId);
            if (!isException(username)) {
                String newPassword = decidePassword(username);
                try {
                    changePassword(scimId, newPassword);
                    if (!checkCredentials(username, newPassword)) {
                        log.error("Wrong credentials : " + username + " : " + newPassword);
                    }
                    log.info("Successfully update password for the user : " + username + " , SCIMId : " + scimId
                            + " , password : " + newPassword);
                    stringBuilder.append(username + "," + newPassword)
                            .append("\n");
                } catch (Exception e) {
                    log.error("Error updating password for the user : " + username + " , SCIMId : " + scimId
                            + " , password : " + newPassword);
                }
            }
        }
        writeToFile(stringBuilder.toString());
    }

    private static String encodeUsernamePassword(String username, String password) {
        return Base64.getEncoder().encodeToString((username + ":" + password).getBytes(UTF_8));
    }

    private static boolean changePassword(String scimId, String newPassword) throws IOException {

        String json = new JSONObject()
                .put("schemas", new JSONArray().put("urn:ietf:params:scim:api:messages:2.0:PatchOp"))
                .put("Operations", new JSONArray()
                        .put(new JSONObject()
                                .put("op", "add")
                                .put("value", new JSONObject().put("password", newPassword))))
                .toString();
        log.info("SCIM change password payload : " + json);

        CloseableHttpClient client = HttpClients.createDefault();
        HttpPatch httpPatch = new HttpPatch(Constants.HOST + "/scim2/Users/" + scimId);
        httpPatch.setHeader("Accept", "application/json");
        httpPatch.setHeader("Content-type", "application/json");
        httpPatch.setHeader("Authorization", "Basic " + encodeUsernamePassword(Constants.USERNAME, Constants.PASSWORD));
        StringEntity entity = new StringEntity(json);
        httpPatch.setEntity(entity);
        CloseableHttpResponse scimResponse = client.execute(httpPatch);
        String stringResponse = EntityUtils.toString(scimResponse.getEntity(), "UTF-8");
        log.info("SCIM change password response : " + stringResponse);
        client.close();

        return true;
    }

    private static JSONArray getAllUsers() throws IOException {

        CloseableHttpClient client = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(Constants.HOST + "/scim2/Users");
        httpGet.setHeader("Accept", "application/json");
        httpGet.setHeader("Authorization", "Basic " + encodeUsernamePassword(Constants.USERNAME, Constants.PASSWORD));
        CloseableHttpResponse scimResponse = client.execute(httpGet);
        String stringResponse = EntityUtils.toString(scimResponse.getEntity(), "UTF-8");
        client.close();
        log.info("SCIm response : " + stringResponse);

        JSONObject jsonResponse = new JSONObject(stringResponse);
        log.info("Total users : " + jsonResponse.get("totalResults"));
        return jsonResponse.getJSONArray("Resources");
    }

    private static boolean isException(String username) {

        if (username.toLowerCase().contains(Constants.SUPER_ADMIN) || username.toLowerCase().contains(Constants.ADMIN)) {
            return true;
        }
        return false;
    }

    private static String decidePassword(String username) {

        if (username.toLowerCase().contains(Constants.ADMIN_USER_1) || username.toLowerCase().contains(Constants.ADMIN_USER_2)) {
            return Constants.GUARDIO_ADMIN_USER_PASSWORD;
        } else if (username.toLowerCase().contains(Constants.LIFE_CUSTOMER_MARCOS_GMAIL_COM)) {
            return Constants.LIFE_CUSTOMER_MARCOS_GMAIL_COM_PASSWORD;
        } else if (username.toLowerCase().contains(Constants.PET_CUSTOMER_MARCOS_GMAIL_COM)) {
            return Constants.PET_CUSTOMER_MARCOS_GMAIL_COM_PASSWORD;
        } else if (username.toLowerCase().contains("@guardio.com")) {
            return Constants.GUARDIO_USER_PASSWORD;
        } else {
            return Constants.OTHER_USER_PASSWORD;
        }
    }

    private static boolean checkCredentials(String username, String password) throws Exception {

        CloseableHttpClient client = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(Constants.HOST + "/scim2/Me");
        httpGet.setHeader("Accept", "application/json");
        httpGet.setHeader("Authorization", "Basic " + encodeUsernamePassword(username, password));
        CloseableHttpResponse scimResponse = client.execute(httpGet);
        String stringResponse = EntityUtils.toString(scimResponse.getEntity(), "UTF-8");
        log.info("SCIM ME response : " + stringResponse);
        client.close();
        if (200 == scimResponse.getStatusLine().getStatusCode()) {
            return true;
        }
        return false;
    }

    private static void writeToFile(String entry) throws IOException {

        Path path = Paths.get("/home/nipun/Desktop/credentials.txt");
        try (BufferedWriter writer = Files.newBufferedWriter(path)) {
            writer.write(entry);
        }
    }
}
