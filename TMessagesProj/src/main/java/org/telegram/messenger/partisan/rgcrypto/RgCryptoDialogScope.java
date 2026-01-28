package org.telegram.messenger.partisan.rgcrypto;

import org.telegram.messenger.DialogObject;
import org.telegram.messenger.MessageObject;
import org.telegram.messenger.UserConfig;

public final class RgCryptoDialogScope {
    private RgCryptoDialogScope() {
    }

    public static String fromMessageObject(MessageObject messageObject) {
        if (messageObject == null) {
            return null;
        }
        long dialogId = messageObject.getDialogId();
        long topicId = messageObject.getTopicId();
        long myUserId = UserConfig.getInstance(messageObject.currentAccount).getClientUserId();
        return fromDialogIdAndTopicId(dialogId, topicId, myUserId);
    }

    public static String fromDialogIdAndTopicId(long dialogId, long topicId) {
        return fromDialogIdAndTopicId(dialogId, topicId, 0);
    }

    public static String fromDialogIdAndTopicId(long dialogId, long topicId, long myUserId) {
        if (DialogObject.isUserDialog(dialogId)) {
            if (myUserId > 0) {
                long a = Math.min(myUserId, dialogId);
                long b = Math.max(myUserId, dialogId);
                return "u:" + a + ":" + b;
            }
            return "u:" + dialogId;
        }
        if (DialogObject.isChatDialog(dialogId)) {
            long chatId = -dialogId;
            if (topicId > 0) {
                return "g:" + chatId + ":t:" + topicId;
            }
            return "g:" + chatId;
        }
        return null;
    }

    public static boolean isCompatibleUserScope(String dialogScope, String envelopeScope, String senderId) {
        if (dialogScope == null || envelopeScope == null || senderId == null) {
            return false;
        }
        if (!dialogScope.startsWith("u:") || !envelopeScope.startsWith("u:")) {
            return false;
        }
        long sender;
        try {
            sender = Long.parseLong(senderId);
        } catch (Exception e) {
            return false;
        }
        long[] dialogIds = parseUserScopeIds(dialogScope);
        if (dialogIds.length == 0) {
            return false;
        }
        if (dialogIds.length == 1) {
            return envelopeScope.equals("u:" + dialogIds[0]) || envelopeScope.equals("u:" + sender);
        }
        long a = dialogIds[0];
        long b = dialogIds[1];
        if (!(sender == a || sender == b)) {
            return false;
        }
        if (envelopeScope.equals("u:" + a) && sender == b) {
            return true;
        }
        if (envelopeScope.equals("u:" + b) && sender == a) {
            return true;
        }
        return envelopeScope.equals(dialogScope);
    }

    private static long[] parseUserScopeIds(String scope) {
        if (scope == null || !scope.startsWith("u:")) {
            return new long[0];
        }
        String rest = scope.substring(2);
        String[] parts = rest.split(":");
        if (parts.length == 1) {
            try {
                return new long[]{Long.parseLong(parts[0])};
            } catch (Exception e) {
                return new long[0];
            }
        } else if (parts.length >= 2) {
            try {
                long a = Long.parseLong(parts[0]);
                long b = Long.parseLong(parts[1]);
                return new long[]{a, b};
            } catch (Exception e) {
                return new long[0];
            }
        }
        return new long[0];
    }
}
