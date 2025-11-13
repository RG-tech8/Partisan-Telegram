package org.telegram.messenger.partisan.ui;

import android.content.Context;
import android.view.View;

import androidx.recyclerview.widget.RecyclerView;

import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.Cells.HeaderCell;
import org.telegram.ui.Cells.TextCheckCell;

public class HeaderItem extends AbstractItem {
    private final String text;

    public HeaderItem(BaseFragment fragment, String text) {
        super(fragment, ItemType.HEADER.ordinal());
        this.text = text;
    }

    public static View createView(Context context) {
        return AbstractItem.initializeView(new HeaderCell(context));
    }

    @Override
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        ((HeaderCell) holder.itemView).setText(text);
    }

    @Override
    public void onClick(View view) {}

    @Override
    public boolean enabled() {
        return false;
    }
}
