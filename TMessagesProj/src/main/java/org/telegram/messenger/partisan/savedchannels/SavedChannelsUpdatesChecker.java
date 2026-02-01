package org.telegram.messenger.partisan.savedchannels;

import android.content.Context;
import android.content.SharedPreferences;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.MessageObject;
import org.telegram.messenger.NotificationCenter;
import org.telegram.messenger.UserConfig;
import org.telegram.messenger.fakepasscode.FakePasscodeUtils;
import org.telegram.messenger.partisan.AbstractChannelChecker;
import org.telegram.messenger.partisan.PartisanLog;
import org.telegram.tgnet.TLObject;
import org.telegram.tgnet.TLRPC;

import java.util.List;
import java.util.Random;

public class SavedChannelsUpdatesChecker extends AbstractChannelChecker {
    private static final String PREFS_PREFIX = "saved_channels_repo_";
    private static final String KEY_USERNAME = "channel_username";
    private static final String KEY_CHAT_ID = "channel_id";
    private static final String KEY_LAST_ID = "last_checked_message_id";
    private static final String KEY_NEXT_CHECK = "next_check_time";
    private static final int MIN_CHECK_DELAY_SEC = 2 * 60 * 60;
    private static final int MAX_CHECK_DELAY_SEC = 3 * 60 * 60;
    private static final Random RANDOM = new Random();

    private final Storage storage;

    public SavedChannelsUpdatesChecker(int currentAccount, Storage storage) {
        super(currentAccount, storage.lastCheckedMessageId);
        this.storage = storage;
    }

    public static void checkUpdate(int currentAccount, boolean force) {
        if (!UserConfig.getInstance(currentAccount).isClientActivated()) {
            return;
        }
        if (FakePasscodeUtils.isFakePasscodeActivated()) {
            return;
        }
        Storage storage = Storage.load(currentAccount);
        if (!force && System.currentTimeMillis() - storage.nextCheckTime <= 0) {
            return;
        }
        SavedChannelsUpdatesChecker checker = new SavedChannelsUpdatesChecker(currentAccount, storage);
        checker.checkUpdate();
    }

    @Override
    protected void checkUpdate() {
        storage.updateNextCheckTime();
        storage.save(currentAccount);
        if (storage.chatId == 0 && storage.chatUsername != null && !storage.chatUsername.isEmpty()) {
            resolveChannelAndCheck();
            return;
        }
        super.checkUpdate();
    }

    @Override
    protected String getLoggingTag() {
        return "SavedChannelsUpdatesChecker";
    }

    @Override
    protected long getChannelId() {
        return storage.chatId;
    }

    @Override
    protected String getChannelUsername() {
        return storage.chatUsername;
    }

    @Override
    protected void processChannelMessages(List<MessageObject> messages) {
        SavedChannelsMessageParser parser = new SavedChannelsMessageParser();
        List<MessageObject> sortedMessages = sortMessageById(messages);
        boolean changed = false;
        UserConfig config = UserConfig.getInstance(currentAccount);
        for (MessageObject message : sortedMessages) {
            if (message.messageOwner.id <= storage.lastCheckedMessageId) {
                continue;
            }
            SavedChannelsMessageParser.ParsingResult result = parser.parseMessage(message);
            if (result == null) {
                continue;
            }
            for (String username : result.toAdd) {
                if (isRepoUsername(username)) {
                    continue;
                }
                if (config.savedChannels.add(username)) {
                    changed = true;
                }
            }
            for (String username : result.toRemove) {
                if (isRepoUsername(username)) {
                    continue;
                }
                if (config.savedChannels.remove(username)) {
                    changed = true;
                }
                if (config.pinnedSavedChannels.remove(username)) {
                    changed = true;
                }
            }
        }
        int lastMessageId = Math.max(getMaxMessageId(messages), storage.lastCheckedMessageId);
        storage.lastCheckedMessageId = lastMessageId;
        storage.save(currentAccount);
        if (changed) {
            config.saveConfig(true);
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.savedChannelsButtonStateChanged);
        }
    }

    private static boolean isRepoUsername(String username) {
        return username != null && username.equalsIgnoreCase(UserConfig.DEFAULT_SAVED_CHANNELS_REPO);
    }

    @Override
    protected void messagesLoadingError() {
    }

    @Override
    protected void usernameResolvingResponseReceived(TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            long chatId = peerToChatId(((TLRPC.TL_contacts_resolvedPeer) response).peer);
            storage.chatId = -chatId;
            storage.save(currentAccount);
        }
        super.usernameResolvingResponseReceived(response, error);
    }

    private long peerToChatId(TLRPC.Peer peer) {
        return peer.channel_id != 0 ? peer.channel_id : peer.chat_id;
    }

    private void resolveChannelAndCheck() {
        PartisanLog.d(getLoggingTag() + ": resolve username '" + storage.chatUsername + "'");
        TLRPC.TL_contacts_resolveUsername req = new TLRPC.TL_contacts_resolveUsername();
        req.username = storage.chatUsername;
        getConnectionsManager().sendRequest(req, (response, error) -> {
            if (response != null) {
                TLRPC.TL_contacts_resolvedPeer res = (TLRPC.TL_contacts_resolvedPeer) response;
                long chatId = peerToChatId(res.peer);
                storage.chatId = -chatId;
                storage.save(currentAccount);
                AndroidUtilities.runOnUIThread(super::checkUpdate);
            } else {
                AndroidUtilities.runOnUIThread(this::messagesLoadingError);
            }
        });
    }

    private static class Storage {
        public String chatUsername;
        public long chatId;
        public long nextCheckTime;
        public int lastCheckedMessageId;

        static Storage load(int account) {
            SharedPreferences prefs = prefs(account);
            Storage storage = new Storage();
            storage.chatUsername = prefs.getString(KEY_USERNAME, null);
            if (storage.chatUsername == null || storage.chatUsername.isEmpty()) {
                storage.chatUsername = defaultChannelUsername(account);
            }
            storage.chatId = prefs.getLong(KEY_CHAT_ID, 0);
            storage.nextCheckTime = prefs.getLong(KEY_NEXT_CHECK, 0);
            storage.lastCheckedMessageId = prefs.getInt(KEY_LAST_ID, 0);
            return storage;
        }

        void save(int account) {
            SharedPreferences.Editor editor = prefs(account).edit();
            editor.putString(KEY_USERNAME, chatUsername);
            editor.putLong(KEY_CHAT_ID, chatId);
            editor.putLong(KEY_NEXT_CHECK, nextCheckTime);
            editor.putInt(KEY_LAST_ID, lastCheckedMessageId);
            editor.apply();
        }

        void updateNextCheckTime() {
            long delay = MIN_CHECK_DELAY_SEC + RANDOM.nextInt(MAX_CHECK_DELAY_SEC - MIN_CHECK_DELAY_SEC);
            nextCheckTime = System.currentTimeMillis() + delay * 1000L;
        }

        private static SharedPreferences prefs(int account) {
            Context context = ApplicationLoader.applicationContext;
            return context.getSharedPreferences(PREFS_PREFIX + account, Context.MODE_PRIVATE);
        }

        private static String defaultChannelUsername(int account) {
            String repo = UserConfig.DEFAULT_SAVED_CHANNELS_REPO;
            return repo == null || repo.isEmpty() ? "testchannelforsomebots" : repo;
        }
    }
}
