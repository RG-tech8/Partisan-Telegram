package org.telegram.messenger.partisan.ui;

import android.content.Context;
import android.view.View;

import java.util.function.Function;

public enum ItemType {
    TOGGLE(ToggleItem::createView),
    BUTTON(ButtonItem::createView),
    HEADER(HeaderItem::createView),
    DELIMITER(DelimiterItem::createView),
    SEEK_BAR(SeekBarItem::createView);

    private final Function<Context, View> viewConstructor;

    ItemType(Function<Context, View> viewConstructor) {
        this.viewConstructor = viewConstructor;
    }

    public View createView(Context context) {
        return viewConstructor.apply(context);
    }
}
