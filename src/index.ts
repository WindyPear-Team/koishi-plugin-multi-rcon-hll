import { Context, Logger, Schema, Session } from 'koishi'
import { Socket } from 'net'
import dayjs from 'dayjs';
import { v4 as uuidv4 } from 'uuid';
import * as Utils from './utils'

export const name = 'multi-rcon-hll'
export const reusable = true
export const inject = ['database']
const logger = new Logger(name)
let onlinesuspicious: Array<string> = []

export interface Config {
    botid: string
    sendto: string
    servers: ServerConfig[]
    customCommands: CustomCommand[]
    enableGamestateCommand?: boolean;
    enableMassMessage?: boolean;
    enableVip?: boolean;
    enableStats?: boolean;
    enableCdKeyRedemption?: boolean;
    superAdminIds?: string[];
}

export interface ServerConfig {
    name: string
    command: string
    host: string
    port: number
    password: string
    allowedGroups?: string[];
}

export interface CustomCommand {
    alias: string
    command: string
}

export const Config: Schema<Config> = Schema.intersect([
    Schema.object({
        botid: Schema.string().required().description('机器人QQ号'),
        sendto: Schema.string().required().description('发送消息的目标群组ID'),
        superAdminIds: Schema.array(Schema.string()).description('超级管理员 ID 列表 (拥有所有权限，包括管理下级管理员)'),
        enableGamestateCommand: Schema.boolean().default(true).description('启用所有服务器的 .查服 指令'),
        enableMassMessage: Schema.boolean().default(false).description('启用所有服务器的 .群发 指令 (需要管理员权限)'),
        enableVip: Schema.boolean().default(false).description('启用所有服务器的 .VIP 指令 (需要管理员权限)'),
        enableStats: Schema.boolean().default(true).description('启用所有服务器的 战绩统计 和 .查战绩 指令'),
        enableCdKeyRedemption: Schema.boolean().default(false).description('启用所有服务器的 卡密兑换VIP 功能'),
    }).description('全局功能开关和超管配置'),
    Schema.object({
        servers: Schema.array(Schema.object({
            name: Schema.string().required().description('服务器名称'),
            command: Schema.string().required().description('指令名（如“hll1”）'),
            host: Schema.string().required().description('服务器地址'),
            port: Schema.number().default(10101).description('HLL RCON 端口（默认 10101）'),
            password: Schema.string().required().description('RCON 密码'),
            allowedGroups: Schema.array(Schema.string()).description('允许使用此服务器指令的群组 ID 列表 (留空则不限制)'),
        })).description('服务器配置列表 (至少配置一个)').required(), // 确保 servers 必填
        customCommands: Schema.array(Schema.object({
            alias: Schema.string().required().description('自定义指令别名（如“踢出”）'),
            command: Schema.string().required().description('实际指令（如“kick”）'),
        })).description('自定义指令映射 (可选)').default([]),
    })
])

export interface VipData {
    id: number
    uid: string
    serverId: string
    expireAt: Date
    remark: string
}

export interface PlayerStats {
    uid: string;
    serverId: string;
    playerName: string;
    kills: number;
    deaths: number;
    teamKills: number;
    lastUpdate: Date;
    isadmin: boolean;
    issuspicious: boolean;
}

export interface GlobalCdKey {
    id: number;
    key: string;
    duration: string;
    remark: string;
    isUsed: boolean;
    usedByUid?: string;
    usedAt?: Date;
    createdAt: Date;
}

export interface ServerCdKey {
    id: number;
    key: string;
    serverId: string;
    duration: string;
    remark: string;
    isUsed: boolean;
    usedByUid?: string;
    usedAt?: Date;
    createdAt: Date;
}

export interface HllSubAdmin {
    userId: string;
    addedBy: string;
    addedAt: Date;
}

declare module 'koishi' {
    interface Tables {
        vip_data: VipData,
        player_stats: PlayerStats,
        global_cdkeys: GlobalCdKey,
        server_cdkeys: ServerCdKey,
        hll_sub_admins: HllSubAdmin,
    }
}

export class HLLConnection {
    private socket: Socket
    private xorKey: Buffer | null = null
    private isConnected = false

    constructor() {
        this.socket = new Socket()
        this.socket.setTimeout(20_000)
    }

    async connect(host: string, port: number, password: string): Promise<void> {
        return new Promise((resolve, reject) => {
            this.socket.connect(port, host, () => {
                this.socket.once('data', (keyData) => {
                    this.xorKey = keyData
                    this._authenticate(password)
                        .then(resolve)
                        .catch(reject)
                })
            })
            this.socket.on('error', (err) => reject(err))
            this.socket.on('timeout', () => reject(new Error('连接超时')))
        })
    }

    private async _authenticate(password: string): Promise<void> {
        return new Promise((resolve, reject) => {
            const authCommand = `login ${password}`
            this.send(authCommand)
            this.receive()
                .then((response) => {
                    if (response.toString().trim() !== 'SUCCESS') {
                        throw new Error('HLL 认证失败：密码错误')
                    }
                    this.isConnected = true
                    resolve()
                })
                .catch(reject)
        })
    }

    send(command: string): void {
        if (!this.xorKey) {
            throw new Error('XOR 密钥未初始化')
        }
        const encoded = this._xor(Buffer.from(command))
        this.socket.write(encoded)
    }

    async receive(): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            let buffer = Buffer.alloc(0)
            const msglen = 32_768
            const onData = (data: Buffer) => {
                const decoded = this._xor(data)
                buffer = Buffer.concat([buffer, decoded])
                if (data.length >= msglen) {
                    this.socket.once('data', onData)
                } else {
                    resolve(buffer)
                }
            }
            this.socket.once('data', onData)
            this.socket.once('error', reject)
            this.socket.once('timeout', () => resolve(buffer))
        })
    }

    private _xor(data: Buffer): Buffer {
        if (!this.xorKey) {
            throw new Error('XOR 密钥未初始化')
        }
        const result = Buffer.alloc(data.length)
        for (let i = 0; i < data.length; i++) {
            result[i] = data[i] ^ this.xorKey[i % this.xorKey.length]
        }
        return result
    }

    close() {
        if (this.socket && !this.socket.destroyed) {
            this.socket.destroy()
        }
        this.isConnected = false
    }
}

export function apply(ctx: Context, config: Config) {

    ctx.model.extend('vip_data', {
        id: 'unsigned', uid: 'string', serverId: 'string',
        expireAt: 'timestamp', remark: 'string',
    }, { primary: 'id', autoInc: true });

    ctx.model.extend('player_stats', {
        uid: 'string', serverId: 'string', playerName: 'string',
        kills: 'integer', deaths: 'integer', teamKills: 'integer',
        lastUpdate: 'timestamp', isadmin: 'boolean', issuspicious: 'boolean',
    }, { primary: ['uid', 'serverId'] });

    ctx.model.extend('global_cdkeys', {
        id: 'unsigned', key: 'string', duration: 'string',
        remark: 'string', isUsed: 'boolean', usedByUid: 'string',
        usedAt: 'timestamp', createdAt: 'timestamp',
    }, { primary: 'id', autoInc: true, unique: ['key'], });

    ctx.model.extend('server_cdkeys', {
        id: 'unsigned', key: 'string', serverId: 'string', duration: 'string',
        remark: 'string', isUsed: 'boolean', usedByUid: 'string',
        usedAt: 'timestamp', createdAt: 'timestamp',
    }, { primary: 'id', autoInc: true });

    ctx.model.extend('hll_sub_admins', {
        userId: 'string',
        addedBy: 'string',
        addedAt: 'timestamp',
    }, { primary: 'userId' });

    const commandMap = new Map<string, string>()
    config.customCommands.forEach(({ alias, command }) => {
        commandMap.set(alias, command)
    })

    config.servers.forEach((server) => {

        const baseCommand = ctx.command(`${server.command} <command:text>`)
            .usage(`(${server.name}) 相关指令`)
            .option('time', '-t <time>', { fallback: '0' });

        baseCommand.action(async ({ session, options }, inputCommand) => {
            if (!inputCommand) return '请输入RCON指令。';
            if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此服务器的命令。';
            if (!await Utils.hasAdminPermission(ctx, session, config, 'sub')) return '权限不足。';
            if (options.time && options.time !== '0') {
                ctx.setTimeout(async () => {
                    const conn = new HLLConnection()
                    try {
                        await conn.connect(server.host, server.port, server.password)
                        const [firstWord, ...rest] = inputCommand.split(' ')
                        const mappedCommand = commandMap.get(firstWord) || firstWord
                        const finalCommand = [mappedCommand, ...rest].join(' ')
                        conn.send(finalCommand)
                        const response = await conn.receive()
                        session.send(`[HLL] ${server.name} 响应：\n${response.toString()}`)
                        return;
                    } catch (error) {
                        session.send(`[HLL] 错误 (${server.name})：${error.message}`)
                        return;
                    } finally {
                        conn.close()
                    }
                }, Utils.parseMs(options.time))
                return `已设置定时 ${options.time} 后执行 ${inputCommand} 。`;
            }
            const conn = new HLLConnection()
            try {
                await conn.connect(server.host, server.port, server.password)
                const [firstWord, ...rest] = inputCommand.split(' ')
                const mappedCommand = commandMap.get(firstWord) || firstWord
                const finalCommand = [mappedCommand, ...rest].join(' ')
                conn.send(finalCommand)
                const response = await conn.receive()
                return `[HLL] ${server.name} 响应：\n${response.toString()}`
            } catch (error) {
                return `[HLL] 错误 (${server.name})：${error.message}`
            } finally {
                conn.close()
            }
        })
            .usage('执行原始 RCON 指令 (需要下级或以上管理员权限)')

        if (config.enableGamestateCommand) {
            baseCommand.subcommand('.查服')
                .action(async ({ session }) => {
                    if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
                    let conn: HLLConnection | null = null;
                    try {
                        conn = new HLLConnection()
                        await conn.connect(server.host, server.port, server.password)
                        conn.send('Get PlayerIds')
                        const playernum = (await conn.receive()).toString().split("	")[0];
                        conn.send('get name')
                        const serverName = (await conn.receive()).toString().trim();
                        conn.send('get gamestate')
                        const response = (await conn.receive()).toString();
                        const lines = response.split('\n');
                        const playersLine = lines.find(line => line.startsWith('Players:'));
                        const scoreLine = lines.find(line => line.startsWith('Score:'));
                        const timeLine = lines.find(line => line.startsWith('Remaining Time:'));
                        const mapLine = lines.find(line => line.startsWith('Map:'));
                        const nextMapLine = lines.find(line => line.startsWith('Next Map:'));
                        const players = playersLine ? playersLine.substring(playersLine.indexOf(':') + 1).trim() : '?';
                        const score = scoreLine ? scoreLine.substring(scoreLine.indexOf(':') + 1).trim() : '?';
                        const time = timeLine ? timeLine.substring(timeLine.indexOf(':') + 1).trim() : '?';
                        const map = mapLine ? mapLine.substring(mapLine.indexOf(':') + 1).trim() : '?';
                        const nextMap = nextMapLine ? nextMapLine.substring(nextMapLine.indexOf(':') + 1).trim() : '?';
                        const [, alliedPlayers = '?', axisPlayers = '?'] = players.match(/Allied:\s*(\d+).*Axis:\s*(\d+)/) || [];
                        const [, alliedScore = '?', axisScore = '?'] = score.match(/Allied:\s*(\d+).*Axis:\s*(\d+)/) || [];
                        return `${serverName} 服务器状态：\n` +
                            `在线玩家: ${playernum}\n` +
                            `阵营人数: 同盟国: ${alliedPlayers} - 轴心国: ${axisPlayers}\n` +
                            `比分: 同盟国: ${alliedScore} - 轴心国: ${axisScore}\n` +
                            `剩余时间: ${time}\n` +
                            `当前地图: ${map}\n` +
                            `下一张地图: ${nextMap}`;
                    } catch (error) {
                        return `[HLL] 错误 (${server.name})：${error.message}`;
                    } finally {
                        if (conn) conn.close();
                    }
                }).usage('查询服务器状态 (所有用户)')
        }

        // === 管理员管理子命令 ===
        baseCommand.subcommand('.添加管理员 <targetUserId:string>', '添加下级管理员 (仅超管可用)')
            .action(async ({ session }, targetUserId) => {
                if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此服务器的命令。';
                if (!await Utils.hasAdminPermission(ctx, session, config, 'super')) {
                    return '权限不足，只有超级管理员才能添加下级管理员。';
                }
                if (!targetUserId) return '请输入要添加的用户ID。';

                // 尝试获取用户名以提供更好的反馈
                let targetUserName = targetUserId;
                try {
                    const user = await session.bot.getUser(targetUserId);
                    if (user?.name) targetUserName = user.name;
                } catch { } // 忽略获取用户信息的错误

                if (config.superAdminIds?.includes(targetUserId)) {
                    return `用户 ${targetUserName} (${targetUserId}) 已经是超级管理员。`;
                }
                const [existingSubAdmin] = await ctx.database.get('hll_sub_admins', { userId: targetUserId });
                if (existingSubAdmin) {
                    return `用户 ${targetUserName} (${targetUserId}) 已经是下级管理员。`;
                }

                try {
                    await ctx.database.create('hll_sub_admins', {
                        userId: targetUserId,
                        addedBy: session.userId!,
                        addedAt: new Date(),
                    });
                    return `已成功添加下级管理员：${targetUserName} (${targetUserId})`;
                } catch (error) {
                    ctx.logger.error(`添加下级管理员 ${targetUserId} 失败: ${error.message}`);
                    return '添加下级管理员失败，请检查日志。';
                }
            });

        baseCommand.subcommand('.删除管理员 <targetUserId:string>', '移除下级管理员 (仅超管可用)')
            .action(async ({ session }, targetUserId) => {
                if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此服务器的命令。';
                if (!await Utils.hasAdminPermission(ctx, session, config, 'super')) {
                    return '权限不足，只有超级管理员才能移除下级管理员。';
                }
                if (!targetUserId) return '请输入要移除的用户ID。';

                // 尝试获取用户名
                let targetUserName = targetUserId;
                try {
                    const user = await session.bot.getUser(targetUserId);
                    if (user?.name) targetUserName = user.name;
                } catch { }

                try {
                    const result = await ctx.database.remove('hll_sub_admins', { userId: targetUserId });
                    if (result.removed > 0) {
                        return `已成功移除下级管理员：${targetUserName} (${targetUserId})`;
                    } else {
                        return '未找到该下级管理员。';
                    }
                } catch (error) {
                    ctx.logger.error(`移除下级管理员 ${targetUserId} 失败: ${error.message}`);
                    return '移除下级管理员失败，请检查日志。';
                }
            });

        baseCommand.subcommand('.列出管理员', '列出所有管理员 (超管及下级管理员可用)')
            .action(async ({ session }) => {
                if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此服务器的命令。';
                if (!await Utils.hasAdminPermission(ctx, session, config, 'sub')) {
                    return '权限不足。';
                }

                const superAdmins = config.superAdminIds || [];
                const subAdmins = await ctx.database.get('hll_sub_admins', {});

                let response = '管理员列表：\n';
                response += '--- 超级管理员 ---\n';
                if (superAdmins.length > 0) {
                    const names = await Promise.all(superAdmins.map(async id => {
                        try { const user = await session.bot.getUser(id); return user?.name ? `${user.name} (${id})` : id; } catch { return id; }
                    }));
                    response += names.join('\n');
                } else {
                    response += '(无)\n';
                }

                response += '\n--- 下级管理员 ---\n';
                if (subAdmins.length > 0) {
                    const names = await Promise.all(subAdmins.map(async admin => {
                        try { const user = await session.bot.getUser(admin.userId); return user?.name ? `${user.name} (${admin.userId})` : admin.userId; } catch { return admin.userId; }
                    }));
                    response += names.join('\n');
                } else {
                    response += '(无)\n';
                }

                return response;
            });


        // === 其他子命令 (VIP, Stats, CDKey) ===

        // .群发 (Uses global config.enableMassMessage, requires Sub Admin)
        if (config.enableMassMessage) {
            baseCommand.subcommand('.群发 <message:text>')
                .action(async ({ session }, message) => {
                    // ... 群发逻辑 (权限检查使用 Utils.hasAdminPermission) ...
                    if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
                    if (!await Utils.hasAdminPermission(ctx, session, config, 'sub')) return '权限不足。';
                    let conn: HLLConnection | null = null;
                    try {
                        conn = new HLLConnection();
                        await conn.connect(server.host, server.port, server.password)
                        conn.send('Get PlayerIds')
                        const playerIdsResponse = (await conn.receive()).toString();
                        const playerLines = playerIdsResponse.split('\n');
                        const playerUids: string[] = [];
                        playerLines.forEach(line => {
                            line = line.trim();
                            if (line === '') return;
                            const lineWithoutNumber = line.replace(/^\d+\s*/, '');
                            const regex = /(?:.*?):\s*([a-f0-9]{32}|765611\d{10,})/g;
                            let match: string[];
                            while ((match = regex.exec(lineWithoutNumber)) !== null) { if (match[1]) playerUids.push(match[1]); }
                        });
                        let successCount = 0;
                        for (const uid of playerUids) {
                            const sendMessageCommand = `Message ${uid} ${message}`;
                            conn.send(sendMessageCommand);
                            await new Promise(resolve => setTimeout(resolve, 50));
                            await conn.receive();
                            successCount++;
                            await ctx.sleep(1000);
                        }
                        return `成功向 ${successCount} 位玩家发送消息(${server.name})。`;
                    } catch (error) {
                        return `[HLL] 错误 (${server.name})：${error.message}`;
                    } finally {
                        if (conn) conn.close();
                    }
                }).usage('群发消息 (需要下级或以上管理员权限)');
        }

        // .VIP (Uses global config.enableVip, requires Sub Admin)
        if (config.enableVip) {
            baseCommand.subcommand('.VIP <uid:string> <duration:string> [remark:string]')
                .action(async ({ session }, uid, durationStr, remark = '添加VIP') => {
                    // ... VIP 逻辑 (权限检查使用 Utils.hasAdminPermission) ...
                    if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
                    if (!await Utils.hasAdminPermission(ctx, session, config, 'sub')) return '权限不足。';
                    let conn: HLLConnection | null = null;
                    try {
                        conn = new HLLConnection();
                        const expireAt = Utils.parseTime(durationStr);
                        if (!expireAt) return '无效的时间格式或时间已过期。请使用例如 1d, 30m, 1y, 5h30m 等格式。';

                        await conn.connect(server.host, server.port, server.password);
                        conn.send(`VipAdd ${uid} "${remark}"`) // 假设 RCON 能处理带引号的备注
                        await conn.receive()
                        await ctx.database.create('vip_data', { uid, serverId: server.command, expireAt, remark })
                        return `已成功为 UID ${uid} 添加 VIP (${server.name})，到期时间：${dayjs(expireAt).format('YYYY-MM-DD HH:mm:ss')}，备注：${remark}。`
                    } catch (error) {
                        return `[HLL] 错误 (${server.name})：${error.message}`;
                    } finally {
                        if (conn) conn.close();
                    }
                }).usage('添加VIP (格式: .VIP <UID> <时间> [备注]) (需要下级或以上管理员权限)');
            baseCommand.subcommand('.恢复VIP')
                .action(async ({ session }) => {
                    // 恢复数据库里面未到期的VIP
                    const conn = new HLLConnection();
                    const vipData = await ctx.database.get('vip_data', { expireAt: { $gt: new Date() } });
                    for (const data of vipData) {
                        if (data.expireAt.getTime() < Date.now()) continue;
                        try {
                            await conn.connect(server.host, server.port, server.password);
                            conn.send(`VipAdd ${data.uid} "${data.remark}"`);
                            await conn.receive();
                        } catch (error) {
                            console.error(`[HLL] 错误 (${server.name})：${error.message}`);
                        }
                    }
                    if (conn) conn.close();
                })
        }

        // Stats commands (Uses global config.enableStats)
        if (config.enableStats) {
            baseCommand.subcommand('.查战绩 <uid:string>')
                .action(async ({ session }, uid) => {
                    // ... 查战绩逻辑 ...
                    if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
                    try {
                        const [stats] = await ctx.database.get('player_stats', { uid, serverId: server.command });
                        if (!stats) return `未找到玩家 UID ${uid} 在服务器 ${server.name} 的战绩信息。`;
                        const kdRatio = stats.deaths === 0 ? stats.kills.toFixed(2) : (stats.kills / stats.deaths).toFixed(2);
                        const lastUpdate = dayjs(stats.lastUpdate).format('YYYY年MM月DD日 HH:mm:ss');
                        return `玩家 ${stats.playerName} (UID: ${uid}) 在 ${server.name} 的战绩：\n` + // 不需要 escape playerName，因为数据库存的就是原始名
                            `击杀总数：${stats.kills}\n` +
                            `死亡总数：${stats.deaths}\n` +
                            `TK总数：${stats.teamKills}\n` +
                            `KD计算：${kdRatio}\n` +
                            `统计至 ${lastUpdate}`;
                    } catch (error) {
                        return `[HLL] 错误 (${server.name})：${error.message}`;
                    }
                }).usage('查询玩家战绩 (所有用户)');

            baseCommand.subcommand('.清除战绩')
                .action(async ({ session }) => {
                    // ... 清除战绩逻辑 (权限检查使用 Utils.hasAdminPermission) ...
                    if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
                    if (!await Utils.hasAdminPermission(ctx, session, config, 'sub')) return '权限不足。';
                    try {
                        const result = await ctx.database.remove('player_stats', { serverId: server.command });
                        return `已成功清除 ${server.name} (${server.command}) 服务器 ${result.removed} 条战绩数据。`;
                    } catch (error) {
                        return `[HLL] 错误 (${server.name})：${error.message}`;
                    }
                }).usage('清除本服务器所有战绩 (需要下级或以上管理员权限)');

            ctx.setInterval(async () => {
                if (!config.enableStats) return; // 检查全局开关
                // ... 战绩统计 Interval 逻辑 ...
                let conn: HLLConnection | null = null;
                try {
                    conn = new HLLConnection();
                    await conn.connect(server.host, server.port, server.password);
                    const killLog = await Utils.getLog(conn, 'showlog 5 kill');
                    const teamKillLog = await Utils.getLog(conn, 'showlog 5 team kill');
                    await Utils.processKillLog(ctx, server.command, killLog, false);
                    await Utils.processKillLog(ctx, server.command, teamKillLog, true);
                    ctx.logger.info(`[${server.name}] 战绩统计已更新。`);
                } catch (error) {
                    ctx.logger.error(`[${server.name}] 战绩统计失败：${error.message}`);
                } finally {
                    if (conn) conn.close();
                }
            }, 300_000);
        }

        // CD-Key commands (Uses global config.enableCdKeyRedemption)
        if (config.enableCdKeyRedemption) {
            baseCommand.subcommand('.生成卡密 <type:string> <duration:string> <count:integer> [remark:string]')
                .action(async ({ session }, type, durationStr, count, remark = 'VIP卡密') => {
                    // ... 生成卡密逻辑 (权限检查使用 Utils.hasAdminPermission 'super') ...
                    if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
                    if (!await Utils.hasAdminPermission(ctx, session, config, 'super')) return '权限不足，只有超级管理员才能生成卡密。';

                    if (!['global', 'server'].includes(type)) return '无效的卡密类型，请指定 "global" 或 "server"。';
                    const durationCheck = Utils.parseTime(durationStr);
                    if (!durationCheck) return '无效的时间格式或时间已过期。请使用例如 1d, 30m, 1y, 5h30m 等格式。';
                    if (!Number.isInteger(count) || count <= 0) return '生成的数量必须是一个正整数。';
                    if (count > 100) return '出于性能考虑，单次最多生成 100 个卡密。';

                    const keysToCreate: (Omit<GlobalCdKey, 'id'> | Omit<ServerCdKey, 'id'>)[] = [];
                    const generatedKeys: string[] = [];
                    const now = new Date();

                    for (let i = 0; i < count; i++) {
                        const newKey = uuidv4();
                        generatedKeys.push(newKey);
                        const commonData = { key: newKey, duration: durationStr, remark, isUsed: false, createdAt: now };
                        if (type === 'global') {
                            keysToCreate.push({ ...commonData });
                        } else {
                            keysToCreate.push({ ...commonData, serverId: server.command });
                        }
                    }

                    try {
                        const tableName = type === 'global' ? 'global_cdkeys' : 'server_cdkeys';
                        await ctx.database.upsert(tableName, keysToCreate as any);
                        //return `成功生成 ${count} 个 ${type === 'global' ? '全局' : `服务器 ${server.name} (${server.command}) 专用`} 卡密 (时长: ${durationStr}, 备注: ${remark})：\n` + generatedKeys.join('\n');
                        const successMessage = `成功生成 ${count} 个 ${type === 'global' ? '全局' : `服务器 ${server.name} (${server.command}) 专用`} 卡密 (时长: ${durationStr}, 备注: ${remark})。`;
                        const privateMessageContent = `${successMessage}\n生成的卡密如下：\n${generatedKeys.join('\n')}`;

                        try {
                            // 尝试发送私聊消息给执行命令的管理员
                            await session.bot.sendPrivateMessage(session.userId!, privateMessageContent);
                            // 如果私聊发送成功，在原频道回复简短确认信息
                            return `${successMessage} 卡密已私聊发送给您。`;
                        } catch (privateMessageError) {
                            // 如果私聊失败 (例如用户未启动私聊或机器人没有权限)
                            ctx.logger.warn(`无法向用户 ${session.userId} 发送私聊卡密: ${privateMessageError.message}`);
                            ctx.logger.info(privateMessageContent);
                            // 在原频道回复完整信息作为备用方案
                            return '发送卡密失败，请在控制台中查看完整卡密信息。';
                        }
                    } catch (error) {
                        if (error.message.includes('UNIQUE')) {
                            return `[HLL] 错误 (${server.name})：生成卡密时遇到重复，请重试。`;
                        }
                        return `[HLL] 错误 (${server.name})：批量生成卡密时发生数据库错误: ${error.message}`;
                    }
                }).usage('批量生成卡密 (格式: .生成卡密 <global|server> <时间> <数量> [备注]) (需要超级管理员权限)');

            baseCommand.subcommand('.卡密兑换 <uid:string> <key:string>')
                .action(async ({ session }, uid, key) => {
                    // ... 卡密兑换逻辑 ...
                    if (server.allowedGroups?.length && !server.allowedGroups.includes(session?.channelId!)) return '本群组不允许使用此命令。';
                    if (!config.enableVip) return 'VIP功能未启用，无法兑换卡密。';

                    let cdKeyRecord: GlobalCdKey | ServerCdKey | null = null;
                    let keyType: 'global' | 'server' = 'server';
                    let durationStr: string = '';
                    let remark: string = '';
                    let isGlobalKeyUsedOnThisServer = false;

                    try {
                        const [serverKey] = await ctx.database.get('server_cdkeys', { key, serverId: server.command });
                        if (serverKey) {
                            if (serverKey.isUsed) return '此服务器卡密已被使用。';
                            cdKeyRecord = serverKey; keyType = 'server'; durationStr = serverKey.duration; remark = serverKey.remark;
                        } else {
                            const [globalKey] = await ctx.database.get('global_cdkeys', { key });
                            if (globalKey) {
                                if (globalKey.isUsed) {
                                    return `您已使用此全局卡密 ${key} 兑换过 VIP。`;
                                } else {
                                }

                                cdKeyRecord = globalKey; keyType = 'global'; durationStr = globalKey.duration; remark = globalKey.remark;
                            }
                        }

                        if (!cdKeyRecord) return '无效的卡密。';
                        const expireAt = Utils.parseTime(durationStr);
                        if (!expireAt) return '卡密关联的时间格式无效。';
                        // 再次检查全局卡密是否已在此服务器为该用户添加过 VIP
                        if (keyType === 'global' && isGlobalKeyUsedOnThisServer) return `您已使用此全局卡密 ${key} 在服务器 ${server.name} 兑换过 VIP。`;

                        let conn: HLLConnection | null = null;
                        try {
                            conn = new HLLConnection();
                            await conn.connect(server.host, server.port, server.password);
                            const finalRemark = `${remark} (卡密: ${key})`;
                            conn.send(`VipAdd ${uid} "${finalRemark}"`);
                            await conn.receive();
                            await ctx.database.create('vip_data', { uid, serverId: server.command, expireAt, remark: finalRemark });

                            const now = new Date();
                            const updateData = { isUsed: true, usedByUid: uid, usedAt: now };
                            // 全局卡密只在它数据库记录为 isUsed=false 时更新一次状态
                            if (keyType === 'global' && !cdKeyRecord.isUsed) {
                                await ctx.database.set('global_cdkeys', { key: cdKeyRecord.key }, updateData);
                            } else if (keyType === 'server') { // 服务器卡密每次兑换都更新（虽然它已经是 isUsed=true 了）
                                await ctx.database.set('server_cdkeys', { id: cdKeyRecord.id }, updateData);
                            }
                            return `卡密 ${key} 兑换成功！已为 UID ${uid} 添加 ${durationStr} VIP (${server.name})，备注：${remark}。`;
                        } catch (rconError) {
                            ctx.logger.error(`[HLL] RCON 操作失败 (${server.name}) 卡密 ${key} for ${uid}: ${rconError.message}`);
                            return `[HLL] 错误 (${server.name})：VIP 添加失败，请联系管理员。错误: ${rconError.message}`;
                        } finally {
                            if (conn) conn.close();
                        }
                    } catch (dbError) {
                        ctx.logger.error(`[HLL] 卡密兑换数据库操作失败 (${server.name}) Key ${key}: ${dbError.message}`);
                        return `[HLL] 错误 (${server.name})：兑换过程中发生数据库错误，请稍后重试。`;
                    }
                }).usage('使用卡密兑换VIP (格式: .卡密兑换 <游戏内UID> <卡密>) (所有用户)');
        }
        //通过uuid添加可疑 指令
        baseCommand.subcommand('.添加可疑玩家 <uuid:string>')
            .action(async ({ session }, uuid) => {
                if (!session?.channelId) return '此命令只能在群组中使用。';
                // 检查是否为设置的管理员或分管
                if (!Utils.hasAdminPermission(ctx, session, config, 'sub')) return '您没有权限使用此命令。';
                //在玩家信息数据库里面设置isadmin
                await ctx.database.set('player_stats', { uid: uuid }, { issuspicious: true });
                return '设置成功';
            })
        baseCommand.subcommand('.删除可疑玩家 <uuid:string>')
            .action(async ({ session }, uuid) => {
                if (!session?.channelId) return '此命令只能在群组中使用。';
                // 检查是否为设置的管理员或分管
                if (!Utils.hasAdminPermission(ctx, session, config, 'sub')) return '您没有权限使用此命令。';
                //在玩家信息数据库里面设置isadmin
                await ctx.database.set('player_stats', { uid: uuid }, { issuspicious: false });
                return '设置成功';
            })

        baseCommand.subcommand('.在线管理员')
            .action(async ({ session }) => {
                // 判断当前会话是否在群组中
                if (!session?.channelId) return '此命令只能在群组中使用。';
                // 查询所有在线玩家
                const conn = new HLLConnection();
                // 连接服务器
                await conn.connect(server.host, server.port, server.password);
                // 发送查询玩家ID的命令
                await conn.send('Get PlayerIds');
                const playerIdsResponse = (await conn.receive()).toString();
                const playerLines = playerIdsResponse.split('\n');
                // const playerUids: string[] = []; // 不再直接用于迭代，但可以通过 Map 获取键集合
                // 使用 Map 存储 UID 到名称的映射，方便按 UID 查找名称
                const playerNamesMap: Map<string, string> = new Map();

                // 遍历 playerLines 数组，查找包含玩家数据的行（跳过头部等）
                playerLines.forEach(line => {
                    line = line.trim();
                    // 跳过空行、头部或其他非玩家数据行
                    if (line === '' || line.startsWith('[HLL]')) {
                         return;
                    }

                    // 假设包含玩家数据的行通过制表符 '\t' 分隔多个玩家条目
                    const playerEntries = line.split('\t');

                    playerEntries.forEach(entry => {
                         entry = entry.trim(); // 清理每个玩家条目字符串
                         if (entry === '') return; // 跳过空的玩家条目

                         // 新的正则表达式：
                         // \d*\s* - 匹配可选的数字和后面的空白字符（处理每个条目开头的序号）
                         // (.*) - 捕获玩家名称（匹配冒号前任意字符）
                         // :\s* - 匹配冒号和后面的空白
                         // ([a-f0-9]{32}|765611\d{10,}) - 捕获玩家ID (32位HEX 或 SteamID64)
                         const regex = /\d*\s*(.*):\s*([a-f0-9]{32}|765611\d{10,})/;

                         const match = entry.match(regex); // 使用 match() 查找一次匹配

                         if (match && match[1] && match[2]) {
                             const playerName = match[1].trim(); // 提取并清理玩家名称 (第1个捕获组)
                             const playerUid = match[2];       // 提取玩家UID (第2个捕获组)

                             // 将 UID 作为键，玩家名称作为值存入 Map
                             playerNamesMap.set(playerUid, playerName);
                         }
                    });
                });

                // *** 以下获取 AdminIds 的代码保持不变，因为它处理的是 Get AdminIds 命令的响应格式 ***
                await conn.send('Get AdminIds');
                const AdminIdsResponse = await (conn.receive()).toString();
                const lines = AdminIdsResponse.split('\n').filter(line => line.trim() !== '');
                // 使用 flatMap 处理每一行，提取 ID
                const adminIds = lines.flatMap(line => {
                    // 使用一个或多个空白字符分割行
                    const parts = line.split(/\s+/).filter(part => part !== '');
                    if (parts.length < 2) {
                        // 如果分割后元素少于2个，说明格式有问题，跳过此行
                        return [];
                    }
                    const idsInLine = [];
                    // 从第二个元素（索引1）开始，每隔3个元素就是ID
                    // 数据格式是: 计数 ID 角色 名称 ID 角色 名称 ...
                    for (let i = 1; i < parts.length; i += 3) {
                        idsInLine.push(parts[i]);
                    }
                    return idsInLine;
                });
                // *** 获取 AdminIds 代码结束 ***

                // 从 Map 中获取所有在线玩家的 UID 列表
                const allOnlinePlayerUids = Array.from(playerNamesMap.keys());

                // 取在线玩家 UID 和 Admin UID 的交集，得到在线管理员的 UIDs
                const onlineAdminsUids = allOnlinePlayerUids.filter(uid => adminIds.includes(uid));

                // 构建要发送的在线管理员名称列表
                const onlineAdminNamesList: string[] = [];
                if (onlineAdminsUids.length > 0) {
                     onlineAdminsUids.forEach((adminUid, index) => {
                         // 从 playerNamesMap 中查找对应的玩家名称
                         const playerName = playerNamesMap.get(adminUid);
                         if (playerName) {
                              // 格式化为 "序号. 玩家名称"
                             onlineAdminNamesList.push(`${index + 1}. ${playerName}`);
                         } else {
                             // 如果因为某种原因这个管理员的名称没在玩家列表里找到（理论上不可能，保险起见）
                             onlineAdminNamesList.push(`${index + 1}. Unknown Player (ID: ${adminUid})`);
                         }
                     });

                     const outputString = onlineAdminNamesList.join('\n');

                     // 打印日志，包含在线管理员名称列表
                     // 注意：这里日志和发送的内容都是格式化好的 "序号. 玩家名称" 列表
                     logger.info(`在线管理员：\n${outputString}`);

                     // 向 session 返回在线管理员的名称列表
                     session.send(outputString);
                } else {
                    // 如果 onlineAdminsUids 数组为空，说明没有找到在线的管理员
                    const noAdminsMessage = "没有在线的管理员。";
                    //logger.info(noAdminsMessage); // 记录日志
                    session.send(noAdminsMessage); // 发送没有找到的提示信息
                }
            })
    })

    // --- Interval Timers (VIP Expiry Check - 保持不变) ---
    ctx.setInterval(async () => {
        // ... VIP 过期检查逻辑 ...
        const now = new Date()
        const expiredVips = await ctx.database.get('vip_data', { expireAt: { $lte: now } })
        if (!expiredVips.length) return;

        for (const vip of expiredVips) {
            const server = config.servers.find(s => s.command === vip.serverId)
            if (!server) {
                ctx.logger.warn(`处理过期VIP时找不到服务器配置：${vip.serverId}, UID: ${vip.uid}`)
                await ctx.database.remove('vip_data', { id: vip.id });
                continue
            }
            // Check global VIP switch
            if (!config.enableVip) {
                await ctx.database.remove('vip_data', { id: vip.id });
                ctx.logger.info(`全局VIP功能已禁用，仅从数据库移除过期记录 UID: ${vip.uid} (${server.name})`);
                continue;
            }

            let conn: HLLConnection | null = null;
            try {
                conn = new HLLConnection();
                await conn.connect(server.host, server.port, server.password)
                conn.send(`VipDel ${vip.uid}`)
                await conn.receive()
                await ctx.database.remove('vip_data', { id: vip.id })
                ctx.logger.info(`UID ${vip.uid} 的 VIP 已过期，已从服务器 ${server.name} 移除。`)
            } catch (error) {
                ctx.logger.error(`移除 UID ${vip.uid} (${server.name}) 的过期 VIP 失败：${error.message}`)
            } finally {
                if (conn) conn.close()
            }
        }
    }, 3600_000)
    //每一分钟查询可疑玩家是否在线
    ctx.setInterval(async () => {
        config.servers.forEach(async server => {
            const conn = new HLLConnection();
            await conn.connect(server.host, server.port, server.password);
            conn.send('Get PlayerIds')
            const playerIdsResponse = (await conn.receive()).toString();
            const playerLines = playerIdsResponse.split('\n');
            const playerUids: string[] = [];
            playerLines.forEach(line => {
                line = line.trim();
                if (line === '') return;
                const lineWithoutNumber = line.replace(/^\d+\s*/, '');
                const regex = /(?:.*?):\s*([a-f0-9]{32}|765611\d{10,})/g;
                let match: string[];
                while ((match = regex.exec(lineWithoutNumber)) !== null) { if (match[1]) playerUids.push(match[1]); }
            });
            for (const uid of playerUids) {
                //检查是否为可疑玩家
                const player = await ctx.database.get('player_stats', { uid: uid });
                if (player[0]?.issuspicious && !onlinesuspicious.includes(uid)) {
                    //logger.info(`可疑玩家 ${uid} 在 ${server.name} 上线`)
                    const d = new Date()
                    ctx.bots.find(bot => bot.selfId === config.botid)?.sendMessage(config.sendto, `可疑玩家 ${uid} 在${d.toDateString()} ${d.toLocaleTimeString()} 上线`)
                    onlinesuspicious.push(uid)
                }
            }
            onlinesuspicious.forEach(online => {
                if (!playerUids.includes(online)) {
                    //logger.info(`可疑玩家 ${online} 下线`)
                    const d = new Date()
                    ctx.bots.find(bot => bot.selfId === config.botid)?.sendMessage(config.sendto, `可疑玩家 ${online} 在${d.toDateString()} ${d.toLocaleTimeString()} 下线`)
                    onlinesuspicious.splice(onlinesuspicious.indexOf(online), 1)
                }
            })
        })
    }, 60_000)
}
