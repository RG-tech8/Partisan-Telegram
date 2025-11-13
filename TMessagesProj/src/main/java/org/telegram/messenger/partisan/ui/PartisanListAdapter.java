package org.telegram.messenger.partisan.ui;

import android.content.Context;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import org.telegram.ui.Components.RecyclerListView;

import java.util.function.Supplier;

public class PartisanListAdapter extends RecyclerListView.SelectionAdapter {
    private final Context context;
    private final AbstractItem[] items;
    private final Supplier<Integer> rowCountSupplier;

    public PartisanListAdapter(Context context, AbstractItem[] items, Supplier<Integer> rowCountSupplier) {
        this.context = context;
        this.items = items;
        this.rowCountSupplier = rowCountSupplier;
    }

    @Override
    public boolean isEnabled(RecyclerView.ViewHolder holder) {
        for (AbstractItem item : items) {
            if (item.positionMatch(holder.getAdapterPosition())) {
                return item.enabled();
            }
        }
        return true;
    }

    @Override
    public int getItemCount() {
        return rowCountSupplier.get();
    }

    @Override
    @NonNull
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        ItemType itemType = ItemType.values()[viewType];
        return new RecyclerListView.Holder(itemType.createView(context));
    }

    @Override
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
        for (AbstractItem item : items) {
            if (item.positionMatch(position)) {
                item.onBindViewHolder(holder, position);
                break;
            }
        }
    }

    @Override
    public int getItemViewType(int position) {
        for (AbstractItem item : items) {
            if (item.positionMatch(position)) {
                return item.getViewType();
            }
        }
        return 0;
    }
}
