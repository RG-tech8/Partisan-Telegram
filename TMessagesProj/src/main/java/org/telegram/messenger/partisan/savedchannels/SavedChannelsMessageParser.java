package org.telegram.messenger.partisan.savedchannels;

import org.telegram.messenger.MessageObject;
import org.telegram.messenger.partisan.Utils;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SavedChannelsMessageParser {
    private static final Pattern USERNAME_PATTERN =
            Pattern.compile("(?i)(?:@|https?://t\\.me/|t\\.me/)([A-Za-z0-9_]{4,})");

    public static final class ParsingResult {
        public final Set<String> toAdd = new HashSet<>();
        public final Set<String> toRemove = new HashSet<>();
    }

    public ParsingResult parseMessage(MessageObject message) {
        if (message == null || message.messageText == null) {
            return null;
        }
        ParsingResult result = new ParsingResult();
        String[] lines = message.messageText.toString().split("\n");
        for (String rawLine : lines) {
            String line = rawLine == null ? "" : rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            boolean remove = false;
            if (line.startsWith("+") || line.startsWith("-")) {
                remove = line.startsWith("-");
                line = line.substring(1).trim();
            }
            Set<String> usernames = extractUsernames(line);
            if (usernames.isEmpty() && isBareUsername(line)) {
                usernames.add(normalizeUsername(line));
            }
            if (usernames.isEmpty()) {
                continue;
            }
            if (remove) {
                result.toRemove.addAll(usernames);
            } else {
                result.toAdd.addAll(usernames);
            }
        }
        if (result.toAdd.isEmpty() && result.toRemove.isEmpty()) {
            return null;
        }
        return result;
    }

    private Set<String> extractUsernames(String text) {
        Set<String> result = new HashSet<>();
        if (text == null || text.isEmpty()) {
            return result;
        }
        Matcher matcher = USERNAME_PATTERN.matcher(text);
        while (matcher.find()) {
            String username = normalizeUsername(matcher.group(1));
            if (!username.isEmpty()) {
                result.add(username);
            }
        }
        return result;
    }

    private boolean isBareUsername(String text) {
        return text != null && text.matches("^[A-Za-z0-9_]{4,}$");
    }

    private String normalizeUsername(String text) {
        if (text == null) {
            return "";
        }
        String username = Utils.removeUsernamePrefixed(text).trim();
        return username.toLowerCase(java.util.Locale.US);
    }
}
