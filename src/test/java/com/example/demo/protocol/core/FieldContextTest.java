package com.example.demo.protocol.core;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FieldContextTest {

    @Test
    void putAndGetInt() {
        FieldContext ctx = FieldContext.create();
        ctx.put("ihl", 5);
        assertThat(ctx.getInt("ihl")).isEqualTo(5);
        assertThat(ctx.hasRead("ihl")).isTrue();
    }

    @Test
    void getIntOnMissingThrows() {
        FieldContext ctx = FieldContext.create();
        assertThatThrownBy(() -> ctx.getInt("nope"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(ctx.hasRead("nope")).isFalse();
    }

    @Test
    void getReturnsRawObject() {
        FieldContext ctx = FieldContext.create();
        ctx.put("options", new byte[]{1, 2});
        assertThat((byte[]) ctx.get("options")).containsExactly(1, 2);
    }

    @Test
    void entityBinding() {
        Object obj = new Object();
        FieldContext ctx = FieldContext.create(obj);
        assertThat(ctx.entity()).isSameAs(obj);
    }
}
