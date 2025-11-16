package org.telegram.ui;

import android.content.Context;
import android.util.Pair;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import android.widget.Toast;

import androidx.recyclerview.widget.LinearLayoutManager;

import org.telegram.SQLite.SQLiteCursor;
import org.telegram.SQLite.SQLiteDatabase;
import org.telegram.SQLite.SQLiteDatabaseWrapper;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ChatObject;
import org.telegram.messenger.DialogObject;
import org.telegram.messenger.LocaleController;
import org.telegram.messenger.MessagesController;
import org.telegram.messenger.NotificationCenter;
import org.telegram.messenger.R;
import org.telegram.messenger.SharedConfig;
import org.telegram.messenger.UserConfig;
import org.telegram.messenger.Utilities;
import org.telegram.messenger.partisan.PartisanLog;
import org.telegram.messenger.partisan.settings.TesterSettings;
import org.telegram.messenger.partisan.Utils;
import org.telegram.messenger.partisan.SecurityChecker;
import org.telegram.messenger.partisan.SecurityIssue;
import org.telegram.messenger.partisan.secretgroups.EncryptedGroupInnerChatStarter;
import org.telegram.messenger.partisan.ui.AbstractItem;
import org.telegram.messenger.partisan.ui.ButtonItem;
import org.telegram.messenger.partisan.ui.DelimiterItem;
import org.telegram.messenger.partisan.ui.HeaderItem;
import org.telegram.messenger.partisan.ui.PartisanListAdapter;
import org.telegram.messenger.partisan.ui.ReadOnlyDataItem;
import org.telegram.messenger.partisan.ui.SeekBarItem;
import org.telegram.messenger.partisan.ui.SimpleEditableDataItem;
import org.telegram.messenger.partisan.ui.ToggleItem;
import org.telegram.messenger.partisan.verification.VerificationRepository;
import org.telegram.messenger.partisan.verification.VerificationStorage;
import org.telegram.messenger.partisan.verification.VerificationUpdatesChecker;
import org.telegram.messenger.partisan.voicechange.VoiceChangeSettings;
import org.telegram.tgnet.TLRPC;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.Components.LayoutHelper;
import org.telegram.ui.Components.RecyclerListView;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.Supplier;

public class TesterSettingsFragment extends BaseFragment {
    private final AbstractItem[] items = {
            new HeaderItem(this, "Update"),
            new SimpleEditableDataItem(this, "Update Channel Id",
                    () -> TesterSettings.updateChannelIdOverride.get().get() != 0 ? Long.toString(TesterSettings.updateChannelIdOverride.get().get()) : "",
                    value -> TesterSettings.updateChannelIdOverride.set(Utilities.parseLong(value))
            ),
            new SimpleEditableDataItem(this, "Update Channel Username", TesterSettings.updateChannelUsernameOverride),
            new ButtonItem(this, "Reset Update", this::resetUpdate),
            new DelimiterItem(this),


            new HeaderItem(this, "Verification"),
            new ButtonItem(this, "Check Verification Updates", this::checkVerificationUpdates),
            new ButtonItem(this, "Reset Verification Last Check Time", this::resetVerificationLastCheckTime),
            new DelimiterItem(this),


            new HeaderItem(this, "Secret Groups"),
            new ToggleItem(this, "Show Sec. Chats From Groups", TesterSettings.showEncryptedChatsFromEncryptedGroups),
            new ToggleItem(this, "Detailed Secret Group Member Status", TesterSettings.detailedEncryptedGroupMemberStatus),
            new ReadOnlyDataItem(this, "Flood Wait",
                    () -> "" + EncryptedGroupInnerChatStarter.getInstance(currentAccount).getFloodWaitRemaining()
            ),
            new DelimiterItem(this),


            new HeaderItem(this, "Voice Changing"),
            new SimpleEditableDataItem(this, "Spectrum Distortion Params", VoiceChangeSettings.spectrumDistortionParams),
            new HeaderItem(this, "World F0 Shift"),
            new SeekBarItem(this, VoiceChangeSettings.f0Shift, 0.2, 2.01, 0.025),
            new HeaderItem(this, "World Formant Ratio"),
            new SeekBarItem(this, VoiceChangeSettings.formantRatio, 0.2, 2.01, 0.025),
            new HeaderItem(this, "Bad S Threshold"),
            new SeekBarItem(this, VoiceChangeSettings.badSThreshold, 0, 15000, 250),
            new HeaderItem(this, "Bad S Cutoff"),
            new SeekBarItem(this, VoiceChangeSettings.badSCutoff, 0, 15000, 250),
            new HeaderItem(this, "Bad Sh Min Threshold"),
            new SeekBarItem(this, VoiceChangeSettings.badShMinThreshold, 0, 15000, 250),
            new HeaderItem(this, "Bad Sh Max Threshold"),
            new SeekBarItem(this, VoiceChangeSettings.badShMaxThreshold, 0, 15000, 250),
            new HeaderItem(this, "Bad Sh Cutoff"),
            new SeekBarItem(this, VoiceChangeSettings.badShCutoff, 0, 15000, 250),
            new ToggleItem(this, "Harvest", VoiceChangeSettings.formantShiftingHarvest),
            new DelimiterItem(this),


            new HeaderItem(this, "Other Settings"),
            new ToggleItem(this, "Show Terminate Sessions Warning",
                    () -> SharedConfig.showSessionsTerminateActionWarning,
                    value -> SharedConfig.showSessionsTerminateActionWarning = value
            ),
            new ToggleItem(this, "Show Plain Backup", TesterSettings.showPlainBackup),
            new ToggleItem(this, "Disable Premium", TesterSettings.premiumDisabled),
            new ToggleItem(this, "Show Hide Dialog Is Not Safe Warning",
                    () -> SharedConfig.showHideDialogIsNotSafeWarning,
                    value -> SharedConfig.showHideDialogIsNotSafeWarning = value
            ),
            new SimpleEditableDataItem(this, "Phone Override", TesterSettings.phoneOverride)
                    .addCondition(() -> SharedConfig.activatedTesterSettingType >= 2),
            new ButtonItem(this, "Reset Security Issues", () -> {
                setSecurityIssues(new HashSet<>());
                SecurityChecker.checkSecurityIssuesAndSave(getParentActivity(), getCurrentAccount(), true);
                Toast.makeText(getParentActivity(), "Reset", Toast.LENGTH_SHORT).show();
            }),
            new ButtonItem(this, "Activate All Security Issues", () -> {
                setSecurityIssues(new HashSet<>(Arrays.asList(SecurityIssue.values())));
                Toast.makeText(getParentActivity(), "Activated", Toast.LENGTH_SHORT).show();
            }),
            new SimpleEditableDataItem(this, "Saved Channels",
                    this::getSavedChannelsValue,
                    this::setSavedChannels,
                    ()  -> Integer.toString(getUserConfig().savedChannels.size())
            ).setMultiline(),
            new ToggleItem(this, "Force Allow Screenshots", TesterSettings.forceAllowScreenshots)
                    .addCondition(() -> SharedConfig.activatedTesterSettingType >= 2),
            new ToggleItem(this, "Save Logcat After Restart", TesterSettings.saveLogcatAfterRestart),
            new ToggleItem(this, "Clear Logs With Cache", TesterSettings.clearLogsWithCache),
            new ToggleItem(this, "Force Search During Deletion", TesterSettings.forceSearchDuringDeletion),
            new ToggleItem(this, "More Timer Values", TesterSettings.moreTimerValues),
            new DelimiterItem(this),


            new HeaderItem(this, "Stats"),
            new ReadOnlyDataItem(this, "Dialogs Count (all type)",
                    createDialogsCountFormatter(did -> true)
            ),
            new ReadOnlyDataItem(this, "Channel Count",
                    createDialogsCountFormatter(did -> ChatObject.isChannelAndNotMegaGroup(-did, currentAccount))
            ),
            new ReadOnlyDataItem(this, "Chat (Groups) Count",
                    createDialogsCountFormatter(did -> did < 0 && !ChatObject.isChannelAndNotMegaGroup(-did, currentAccount))
            ),
            new ReadOnlyDataItem(this, "User Chat Count",
                    createDialogsCountFormatter(did -> did > 0)
            ),
            new ReadOnlyDataItem(this, "Memory DB size",
                    () -> getMemoryDbSize() != null ? AndroidUtilities.formatFileSize(getMemoryDbSize()) : "error")
                    .setOnClickListener(this::showMemoryDialog)
                    .addCondition(() -> getMessagesStorage().fileProtectionEnabled()),
            new ReadOnlyDataItem(this, "Account num", () -> Integer.toString(currentAccount)),
            new DelimiterItem(this),
    };

    private Supplier<String> createDialogsCountFormatter(Predicate<Long> condition) {
        return () -> {
            long count = getAllDialogs().stream().filter(d -> condition.test(d.id)).count();
            if (isDialogEndReached()) {
                return Long.toString(count);
            } else {
                return count + "(not all)";
            }
        };
    }

    private boolean isDialogEndReached() {
        MessagesController controller = getMessagesController();
        return controller.isDialogsEndReached(0) && controller.isServerDialogsEndReached(0)
                && (!hasArchive() || controller.isDialogsEndReached(1) && controller.isServerDialogsEndReached(1));
    }

    private boolean hasArchive() {
        MessagesController controller = MessagesController.getInstance(currentAccount);
        if (controller.dialogs_dict.get(DialogObject.makeFolderDialogId(1)) == null) {
            return false;
        }
        List<TLRPC.Dialog> dialogs = controller.getDialogs(1);
        return dialogs != null && !dialogs.isEmpty();
    }

    private void setSecurityIssues(Set<SecurityIssue> issues) {
        SharedConfig.ignoredSecurityIssues = new HashSet<>();
        for (int a = 0; a < UserConfig.MAX_ACCOUNT_COUNT; a++) {
            UserConfig config = UserConfig.getInstance(a);
            if (!config.isClientActivated()) {
                continue;
            }
            config.currentSecurityIssues = issues;
            config.ignoredSecurityIssues = new HashSet<>();
            config.lastSecuritySuggestionsShow = 0;
            config.showSecuritySuggestions = !issues.isEmpty();
            config.saveConfig(false);
        }
    }

    private String getSavedChannelsValue() {
        return getUserConfig().savedChannels.stream().reduce("", (acc, name) -> {
            String result = acc;
            if (!acc.isEmpty()) {
                result += "\n";
            }
            if (getUserConfig().pinnedSavedChannels.contains(name)) {
                result += "*";
            }
            result += name;
            return result;
        });
    }

    private void setSavedChannels(String text) {
        getUserConfig().pinnedSavedChannels = new ArrayList<>();
        getUserConfig().savedChannels = new HashSet<>();
        for (String line : text.split("\n")) {
            if (line.isEmpty()) {
                continue;
            }
            String name = line.replace("*", "");
            if (line.startsWith("*")) {
                getUserConfig().pinnedSavedChannels.add(name);
            }
            getUserConfig().savedChannels.add(name);
        }
        getUserConfig().saveConfig(false);
    }

    private void resetUpdate() {
        PartisanLog.d("pendingPtgAppUpdate: reset 4");
        SharedConfig.pendingPtgAppUpdate = null;
        SharedConfig.saveConfig();
        Toast.makeText(getParentActivity(), "Reset", Toast.LENGTH_SHORT).show();
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.appUpdateAvailable);
    }

    private void checkVerificationUpdates() {
        VerificationUpdatesChecker.checkUpdate(currentAccount, true);
        Toast.makeText(getParentActivity(), "Check started", Toast.LENGTH_SHORT).show();
    }

    private void resetVerificationLastCheckTime() {
        for (VerificationStorage storage : VerificationRepository.getInstance().getStorages()) {
            VerificationRepository.getInstance().saveNextCheckTime(storage.chatId, 0);
        }
        Toast.makeText(getParentActivity(), "Reset", Toast.LENGTH_SHORT).show();
    }

    private Long getMemoryDbSize() {
        Long dbSize = null;
        SQLiteDatabase database = getMessagesStorage().getDatabase();
        if (database instanceof SQLiteDatabaseWrapper) {
            SQLiteDatabaseWrapper wrapper = (SQLiteDatabaseWrapper)database;
            SQLiteDatabase memoryDatabase = wrapper.getMemoryDatabase();
            try {
                SQLiteCursor cursor = memoryDatabase.queryFinalized("select page_count * page_size from pragma_page_count(), pragma_page_size()");
                if (cursor.next()) {
                    dbSize = cursor.longValue(0);
                }
                cursor.dispose();
            } catch (Exception ignore) {
            }
        }
        return dbSize;
    }

    private void showMemoryDialog() {
        List<Pair<String, Long>> tableSizes = getTableSizes();
        String message = tableSizes.stream()
                .map(pair -> pair.first + " = " + AndroidUtilities.formatFileSize(pair.second) + "\n")
                .reduce(String::concat)
                .orElse("");

        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setMessage(message);
        builder.setTitle(LocaleController.getString(R.string.AppName));
        builder.setPositiveButton(LocaleController.getString(R.string.OK), null);
        AlertDialog alertDialog = builder.create();
        showDialog(alertDialog);
    }

    private List<Pair<String, Long>> getTableSizes() {
        List<Pair<String, Long>> tableSizes = new ArrayList<>();
        SQLiteDatabase database = getMessagesStorage().getDatabase();
        if (database instanceof SQLiteDatabaseWrapper) {
            SQLiteDatabaseWrapper wrapper = (SQLiteDatabaseWrapper)database;
            SQLiteDatabase memoryDatabase = wrapper.getMemoryDatabase();
            try {
                SQLiteCursor cursor = memoryDatabase.queryFinalized("SELECT name, SUM(pgsize) size FROM \"dbstat\" GROUP BY name ORDER BY size DESC LIMIT 20");
                while (cursor.next()) {
                    String name = cursor.stringValue(0);
                    long size = cursor.longValue(1);
                    tableSizes.add(new Pair<>(name, size));
                }
                cursor.dispose();
            } catch (Exception e) {
                PartisanLog.e("Error", e);
            }
        }
        return tableSizes;
    }

    private PartisanListAdapter listAdapter;
    private RecyclerListView listView;

    private int rowCount;

    public TesterSettingsFragment() {
        super();
    }

    @Override
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        updateRows();
        return true;
    }

    @Override
    public View createView(Context context) {
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setAllowOverlayTitle(false);
        actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() {
            @Override
            public void onItemClick(int id) {
                if (id == -1) {
                    finishFragment();
                }
            }
        });

        fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) fragmentView;

        actionBar.setTitle("Tester settings");
        frameLayout.setTag(Theme.key_windowBackgroundGray);
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        listView = new RecyclerListView(context);
        listView.setLayoutManager(new LinearLayoutManager(context, LinearLayoutManager.VERTICAL, false) {
            @Override
            public boolean supportsPredictiveItemAnimations() {
                return false;
            }
        });
        listView.setVerticalScrollBarEnabled(false);
        listView.setItemAnimator(null);
        listView.setLayoutAnimation(null);
        frameLayout.addView(listView, LayoutHelper.createFrame(LayoutHelper.MATCH_PARENT, LayoutHelper.MATCH_PARENT));
        listView.setAdapter(listAdapter = new PartisanListAdapter(context, items, () -> rowCount));
        listView.setOnItemClickListener((view, position) -> {
            for (AbstractItem item : items) {
                if (item.positionMatch(position)) {
                    item.onClick(view);
                    break;
                }
            }
        });

        return fragmentView;
    }

    @Override
    public void onResume() {
        super.onResume();
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private void updateRows() {
        rowCount = 0;
        for (AbstractItem item : items) {
            if (item.needAddRow()) {
                item.setPosition(rowCount++);
            }
        }
    }

    @Override
    public void onConfigurationChanged(android.content.res.Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        if (listView != null) {
            ViewTreeObserver obs = listView.getViewTreeObserver();
            obs.addOnPreDrawListener(new ViewTreeObserver.OnPreDrawListener() {
                @Override
                public boolean onPreDraw() {
                    listView.getViewTreeObserver().removeOnPreDrawListener(this);
                    return true;
                }
            });
        }
    }

    private List<TLRPC.Dialog> getAllDialogs() {
        return Utils.getAllDialogs(currentAccount);
    }
}

