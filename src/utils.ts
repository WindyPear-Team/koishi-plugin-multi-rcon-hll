import { Context, Schema, Session } from 'koishi'
import { HLLConnection, Config, PlayerStats } from './';
import dayjs from 'dayjs';


export async function getLog(conn: HLLConnection, command: string): Promise<string> {
    conn.send(command);
    const response = await conn.receive();
    return response.toString();
}

export async function processKillLog(ctx: Context, serverId: string, log: string, isTeamKill: boolean): Promise<void> {
    // ... processKillLog 逻辑 ...
    const lines = log.split('\n');
    const uidsInLog = new Set<string>();
    const parsedEvents: { killerUid: string, killerName: string, victimUid: string, victimName: string, isTk: boolean }[] = [];

    // 1. Parse log, collect UIDs and events
    for (const line of lines) {
        const match = isTeamKill ? teamKillRegex.exec(line) : killRegex.exec(line);
        if (match) {
            const killerUid = match[3];
            const victimUid = match[6];
            if (killerUid) uidsInLog.add(killerUid);
            if (victimUid) uidsInLog.add(victimUid);
            if (killerUid && victimUid) {
                parsedEvents.push({
                    killerUid, killerName: match[1].trim(),
                    victimUid, victimName: match[4].trim(),
                    isTk: isTeamKill
                });
            }
        }
    }

    if (!parsedEvents.length) return;

    // 2. Preload existing data for involved players
    const playerCache = new Map<string, PlayerStats>();
    if (uidsInLog.size > 0) {
        const existingPlayers = await ctx.database.get('player_stats', { uid: { $in: Array.from(uidsInLog) }, serverId });
        existingPlayers.forEach(p => playerCache.set(p.uid, p));
    }

    // 3. Aggregate updates
    const statsToUpdate = new Map<string, PlayerStats>();
    const now = new Date();

    for (const event of parsedEvents) {
        // Killer
        let killerStats = statsToUpdate.get(event.killerUid);
        if (!killerStats) {
            const existing = playerCache.get(event.killerUid);
            killerStats = existing ? {
                ...existing, // 保留 existing 对象中的所有现有属性 (包括 uid, serverId, playerName, kills, deaths, teamKills, lastUpdate 等)
                isadmin: existing.isadmin ?? false, // 如果 existing.isadmin 为 null 或 undefined，则默认为 false
                issuspicious: existing.issuspicious ?? false // 如果 existing.issuspicious 为 null 或 undefined，则默认为 false
            } : {
                // 如果 existing 对象不存在，则创建新的对象并设置初始值
                uid: event.killerUid,
                serverId,
                playerName: event.killerName,
                kills: 0,
                deaths: 0,
                teamKills: 0,
                lastUpdate: now,
                isadmin: false, // 新建时默认为 false
                issuspicious: false // 新建时默认为 false
            };
            if (!existing) playerCache.set(event.killerUid, killerStats);
        }
        killerStats.playerName = event.killerName;
        killerStats.kills += 1;
        if (event.isTk) killerStats.teamKills += 1;
        killerStats.lastUpdate = now;
        statsToUpdate.set(event.killerUid, killerStats);

        // Victim
        let victimStats = statsToUpdate.get(event.victimUid);
        if (!victimStats) {
            const existing = playerCache.get(event.victimUid);
            victimStats = existing ? {
                ...existing,
                isadmin: existing.isadmin ?? false,
                issuspicious: existing.issuspicious ?? false
            } : {
                uid: event.victimUid,
                serverId,
                playerName: event.victimName,
                kills: 0,
                deaths: 0,
                teamKills: 0,
                lastUpdate: now,
                isadmin: false,
                issuspicious: false
            };
            if (!existing) playerCache.set(event.victimUid, victimStats);
        }
        victimStats.playerName = event.victimName;
        victimStats.deaths += 1;
        victimStats.lastUpdate = now;
        statsToUpdate.set(event.victimUid, victimStats);
    }

    // 4. Batch Upsert
    if (statsToUpdate.size > 0) {
        try {
            await ctx.database.upsert('player_stats', Array.from(statsToUpdate.values()));
        } catch (dbError) {
            ctx.logger.error(`[HLL] 批量更新战绩数据库失败 (${serverId}): ${dbError.message}`);
        }
    }
}


const killRegex = /KILL: (.*)\((Allies|Axis)\/(.*?)\)\s*->\s*(.*)\((Allies|Axis)\/(.*?)\)\s*with\s*(.*)/;
const teamKillRegex = /TEAM KILL: (.*)\((Allies|Axis)\/(.*?)\)\s*->\s*(.*)\((Allies|Axis)\/(.*?)\)\s*with\s*(.*)/;


export async function hasAdminPermission(
    ctx: Context,
    session: Session,
    config: Config,
    requiredLevel: 'super' | 'sub'
): Promise<boolean> {
    const userId = session?.userId;
    if (!userId) return false; // No user ID, no permission

    if (config.superAdminIds?.includes(userId)) {
        return true;
    }

    if (requiredLevel === 'super') {
        return false;
    }

    if (requiredLevel === 'sub') {
        const [subAdmin] = await ctx.database.get('hll_sub_admins', { userId: userId });
        return !!subAdmin; // Return true if subAdmin record exists
    }

    return false; // Should not reach here, but default to false
}


export function parseTime(timeStr: string): Date | null {
    let totalSeconds = 0;
    let matched = false;
    const regex = /(\d+)([dmyhs])/g;
    let match;
    while ((match = regex.exec(timeStr)) !== null) {
        matched = true;
        const value = parseInt(match[1]);
        if (isNaN(value) || value <= 0) return null;
        const unit = match[2];
        switch (unit) {
            case 's': totalSeconds += value; break;
            case 'h': totalSeconds += value * 3600; break;
            case 'd': totalSeconds += value * 86400; break;
            case 'm': totalSeconds += value * 2592000; break; // 30 days
            case 'y': totalSeconds += value * 31536000; break; // 365 days
            default: return null;
        }
    }
    if (!matched) return null;
    const futureDate = dayjs().add(totalSeconds, 'seconds');
    if (futureDate.isBefore(dayjs())) return null;
    return futureDate.toDate();
}

export function parseMs(timeStr: string): number | null {
    let totalSeconds = 0;
    let matched = false;
    const regex = /(\d+)([dmyhs])/g;
    let match;
    while ((match = regex.exec(timeStr)) !== null) {
        matched = true;
        const value = parseInt(match[1]);
        if (isNaN(value) || value <= 0) return null;
        const unit = match[2];
        switch (unit) {
            case 's': totalSeconds += value; break;
            case 'h': totalSeconds += value * 3600; break;
            case 'd': totalSeconds += value * 86400; break;
            case 'm': totalSeconds += value * 2592000; break; // 30 days
            case 'y': totalSeconds += value * 31536000; break; // 365 days
            default: return null;
        }
    }
    if (!matched) return null;
    return totalSeconds * 1000;
}