package com.actiongate.policy;

/** What the policy requires for commands assessed at one risk level. */
public record LevelRule(boolean approval, boolean biometric, boolean block) {}
