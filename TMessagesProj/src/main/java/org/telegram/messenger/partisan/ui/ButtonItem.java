package org.telegram.messenger.partisan.ui;

import android.content.Context;
import android.view.View;

import androidx.recyclerview.widget.RecyclerView;

import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.Cells.TextSettingsCell;

public class ButtonItem extends AbstractItem {
    private final String text;
    private final Runnable onClick;

    public ButtonItem(BaseFragment fragment, String text, Runnable onClick) {
        super(fragment, ItemType.BUTTON.ordinal());
        this.text = text;
        this.onClick = onClick;
    }

    public static View createView(Context context) {
        return AbstractItem.initializeView(new TextSettingsCell(context));
    }

    @Override
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        ((TextSettingsCell) holder.itemView).setText(text, true);
    }

    @Override
    public void onClick(View view) {
        onClick.run();
    }

    @Override
    public boolean enabled() {
        return true;
    }
}
