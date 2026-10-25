package com.actiongate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.actiongate.risk.PathUtil;
import com.actiongate.risk.SensitivePaths;
import com.actiongate.risk.ShellParser;
import com.actiongate.util.Json;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MiscTest {
    @Test
    void jsonRoundTripAndStrictness() {
        Map<String, Object> m = Json.parseObject("{\"a\":[1,2.5,true,null,\"x\\n\\u0041\"],\"b\":{\"c\":\"d\"}}");
        assertEquals(List.of(1L, 2.5, true), ((List<?>) m.get("a")).subList(0, 3));
        assertEquals("x\nA", ((List<?>) m.get("a")).get(4));
        assertEquals(m, Json.parseObject(Json.write(m)));
        for (String bad : new String[]{"{", "{\"a\":}", "[1,]", "{\"a\":1} x", "\"unterminated", "{'a':1}", "nul"})
            assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), bad);
        assertThrows(IllegalArgumentException.class, () -> Json.parse("[".repeat(100) + "]".repeat(100)));
    }

    @Test
    void pathNormalisation() {
        String home = "c:/users/alice";
        assertEquals("c:/windows/system32", PathUtil.normalize("C:\\Windows\\System32\\", "/", home));
        assertEquals("c:/users/alice/proj/a", PathUtil.normalize("a", "c:/users/alice/proj", home));
        assertEquals("c:/users/alice", PathUtil.normalize("../..", "c:/users/alice/proj/x", home));
        assertEquals(home, PathUtil.normalize("~", "/", home));
        assertEquals(home + "/.ssh", PathUtil.normalize("$HOME/.ssh", "/", home));
        assertEquals(home + "/.ssh", PathUtil.normalize("%USERPROFILE%\\.ssh", "/", home));
        assertEquals("c:/windows", PathUtil.normalize("/mnt/c/Windows", "/", home));
        assertEquals("/", PathUtil.normalize("/ab/..", "/", home));
        assertEquals("c:/users", PathUtil.normalize("/c/Users", "/", home), "git-bash style drive paths");
        assertEquals("c:/", PathUtil.normalize("C:\\", "/", home));
        assertTrue(PathUtil.isInside("c:/a/b", "c:/a"));
        assertFalse(PathUtil.isInside("c:/ab", "c:/a"));
        assertTrue(PathUtil.hasUnresolved("$UNKNOWN/x", home));
        assertFalse(PathUtil.hasUnresolved("$HOME/x", home));
    }

    @Test
    void sensitivePathHeuristics() {
        for (String s : new String[]{"c:/users/a/.ssh/id_rsa", "/home/a/.aws/credentials", "/p/.env", "/p/.env.production", "/p/server.pem", "/p/.npmrc"})
            assertTrue(SensitivePaths.isSensitive(s), s);
        for (String s : new String[]{"/p/.env.example", "/p/readme.md", "/p/src/Main.java", "/home/a/id_rsa.pub"})
            assertFalse(SensitivePaths.isSensitive(s), s);
    }

    @Test
    void parserSplitsOperatorsRespectingQuotes() {
        var p = ShellParser.parse("echo 'a;b' && ls | wc -l; rm \"x y\" > out.txt 2>&1");
        assertEquals(4, p.segments().size());
        assertEquals("a;b", p.segments().get(0).words().get(1).text());
        assertEquals("|", p.segments().get(1).opAfter());
        assertEquals("x y", p.segments().get(3).words().get(1).text());
        assertEquals(2, p.segments().get(3).redirects().size());
        assertFalse(p.malformed());
        assertTrue(ShellParser.parse("echo \"x").malformed());
        assertEquals(1, ShellParser.parse("echo $(rm -rf /)").segments().get(0).nested().size());
    }
}
