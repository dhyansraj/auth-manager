package io.mcpmesh.auth.manager.theme;

/**
 * Rolling-restart status of the platform-kc StatefulSet, exposed to the UI so
 * it can show a progress indicator after a theme is uploaded.
 */
public record RolloutStatus(State state, int progress) {

    public enum State { READY, ROLLING_OUT, FAILED }

    public static RolloutStatus ready() {
        return new RolloutStatus(State.READY, 100);
    }

    public static RolloutStatus rollingOut(int progress) {
        return new RolloutStatus(State.ROLLING_OUT, Math.max(0, Math.min(99, progress)));
    }

    public static RolloutStatus failed() {
        return new RolloutStatus(State.FAILED, 0);
    }
}
