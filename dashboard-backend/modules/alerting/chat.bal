// Google Chat delivery, matching the EXACT webhook contract already used by this org's own
// build-failure notifier (verified by reading ballerina-release/dependabot/notify_chat.py and
// dependabot/constants.py):
//
//   POST https://chat.googleapis.com/v1/spaces/{CHAT_ID}/messages?key={CHAT_KEY}&token={CHAT_TOKEN}
//   Content-Type: application/json
//   {"text": "<message>"}
//
// Reusing this exact channel/format rather than inventing a new one - it's the established path
// in this org, the secrets already exist (BALLERINA_CHAT_ID / BALLERINA_CHAT_KEY /
// BALLERINA_CHAT_TOKEN at the GitHub org level), and it keeps alert delivery consistent with every
// other automated notification this org already receives. Moved from the standalone
// choreo-alerting component unchanged - see diff.bal's header comment.

import ballerina/http;
import ballerina/os;

configurable string chatId = os:getEnv("CHAT_ID");
configurable string chatKey = os:getEnv("CHAT_KEY");
configurable string chatToken = os:getEnv("CHAT_TOKEN");

final http:Client chatClient = check new ("https://chat.googleapis.com");

public function sendChatMessage(string text) returns error? {
    if chatId == "" || chatKey == "" || chatToken == "" {
        return error("CHAT_ID/CHAT_KEY/CHAT_TOKEN are not configured - refusing to silently drop an alert; fix the deployment's env vars");
    }
    http:Response response = check chatClient->post(
        string `/v1/spaces/${chatId}/messages?key=${chatKey}&token=${chatToken}`,
        {text},
        headers = {"Content-Type": "application/json; charset=UTF-8"}
    );
    if response.statusCode != 200 {
        return error(string `Chat webhook returned ${response.statusCode}: ${check response.getTextPayload()}`);
    }
}
