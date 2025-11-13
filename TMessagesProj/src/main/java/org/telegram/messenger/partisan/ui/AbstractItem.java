package org.telegram.messenger.partisan.ui;

import android.view.View;

import androidx.recyclerview.widget.RecyclerView;

import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;

import java.util.function.Supplier;

public abstract class AbstractItem {
    private int position = -1;
    private final int viewType;
    protected final BaseFragment fragment;
    private Supplier<Boolean> condition = null;

    protected AbstractItem(BaseFragment fragment, int viewType) {
        this.fragment = fragment;
        this.viewType = viewType;
    }

    public void setPosition(int position) {
        this.position = position;
    }

    public boolean positionMatch(int targetPosition) {
        return position == targetPosition;
    }

    public int getViewType() {
        return viewType;
    }

    public AbstractItem addCondition(Supplier<Boolean> condition) {
        this.condition = condition;
        return this;
    }

    public boolean needAddRow() {
        if (condition != null) {
            return condition.get();
        }
        return true;
    }

    protected static View initializeView(View view) {
        view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        return view;
    }

    public abstract void onBindViewHolder(RecyclerView.ViewHolder holder, int position);
    public abstract void onClick(View view);
    public abstract boolean enabled();
}
