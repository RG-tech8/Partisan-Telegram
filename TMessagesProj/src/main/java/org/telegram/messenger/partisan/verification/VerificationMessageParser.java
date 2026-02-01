package org.telegram.messenger.partisan.verification;

import org.telegram.messenger.MessageObject;
import org.telegram.messenger.partisan.Utils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class VerificationMessageParser {
    public static class ParsingResult {
        List<VerificationChatInfo> chatsToAdd = new ArrayList<>();
        List<VerificationChatInfo> chatsToRemove = new ArrayList<>();
    }
    private int currentChatType;

    public ParsingResult parseMessage(MessageObject message) {
        if (message.messageText == null) {
            return null;
        }
        currentChatType = -1;

        ParsingResult result = new ParsingResult();
        try {
            String[] lines = message.messageText.toString().split("\n");
            for (String line : lines) {
                if (line.startsWith("#")) {
                    processControlLine(line.substring(1).trim());
                } else if (currentChatType > 0) {
                    if (line.startsWith("+")) {
                        String payload = line.substring(1).trim();
                        if (!payload.isEmpty()) {
                            result.chatsToAdd.add(parseChatInfo(payload));
                        }
                    } else if (line.startsWith("-")) {
                        String payload = line.substring(1).trim();
                        if (!payload.isEmpty()) {
                            VerificationChatInfo info = parseChatInfo(payload);
                            result.chatsToRemove.add(info);
                        }
                    }
                }
            }
            return result;
        } catch (Exception ignore) {
        }
        return null;
    }

    private VerificationChatInfo parseChatInfo(String chatInfoStr) {
        VerificationChatInfo info = new VerificationChatInfo();
        info.type = currentChatType;
        String normalized = chatInfoStr.trim();
        if (normalized.contains("=")) {
            String[] parts = normalized.split("=", 2);
            info.username = Utils.removeUsernamePrefixed(parts[0].trim());
            info.chatId = Math.abs(Long.parseLong(parts[1].trim()));
        } else {
            info.username = null;
            info.chatId = Math.abs(Long.parseLong(normalized));
        }
        return info;
    }

    private void processControlLine(String command) {
        if (command.equals("verified")) {
            currentChatType = VerificationRepository.TYPE_VERIFIED;
        } else if (command.equals("scam")) {
            currentChatType = VerificationRepository.TYPE_SCAM;
        } else if (command.equals("fake")) {
            currentChatType = VerificationRepository.TYPE_FAKE;
        }
    }
}
