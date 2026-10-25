package com.actiongate.support;

import com.actiongate.enforcement.AuthorizedOperation;
import com.actiongate.enforcement.ExecutionBoundary;
import com.actiongate.model.CommandRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Simulated execution boundary: records releases, never runs anything. */
public final class RecordingBoundary implements ExecutionBoundary {
    public final List<String> released = Collections.synchronizedList(new ArrayList<>());

    @Override
    public void release(CommandRequest request, AuthorizedOperation authorization) {
        released.add(request.command());
    }
}
