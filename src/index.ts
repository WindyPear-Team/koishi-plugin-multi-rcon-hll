import { Context, Schema } from 'koishi'
import { Socket } from 'net'

export const name = 'multi-rcon-hll'

export interface Config {
  servers: ServerConfig[]
  customCommands: CustomCommand[]
}

export interface ServerConfig {
  name: string
  command: string
  host: string
  port: number
  password: string
}

export interface CustomCommand {
  alias: string
  command: string
}

export const Config: Schema<Config> = Schema.object({
  servers: Schema.array(Schema.object({
    name: Schema.string().required().description('服务器名称'),
    command: Schema.string().required().description('指令名（如“hll1”）'),
    host: Schema.string().required().description('服务器地址'),
    port: Schema.number().default(10101).description('HLL RCON 端口（默认 10101）'),
    password: Schema.string().required().description('RCON 密码'),
  })).description('服务器配置'),
  customCommands: Schema.array(Schema.object({
    alias: Schema.string().required().description('自定义指令别名（如“踢出”）'),
    command: Schema.string().required().description('实际指令（如“kick”）'),
  })).description('自定义指令映射'),
})

class HLLConnection {
  private socket: Socket
  private xorKey: Buffer | null = null
  private isConnected = false

  constructor() {
    this.socket = new Socket()
    this.socket.setTimeout(20_000) // 20 秒超时
  }

  async connect(host: string, port: number, password: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket.connect(port, host, () => {
        // 接收 XOR 密钥
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
      // 发送认证命令
      const authCommand = `login ${password}`
      this.send(authCommand)

      // 接收认证响应
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

        // 检查是否继续接收数据
        if (data.length >= msglen) {
          this.socket.once('data', onData)
        } else {
          resolve(buffer)
        }
      }

      this.socket.once('data', onData)
      this.socket.once('error', reject)
      this.socket.once('timeout', () => resolve(buffer)) // 超时返回已接收数据
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
    this.socket.destroy()
    this.isConnected = false
  }
}

export function apply(ctx: Context, config: Config) {
  const { servers, customCommands } = config

  // 自定义指令映射表
  const commandMap = new Map<string, string>()
  customCommands.forEach(({ alias, command }) => {
    commandMap.set(alias, command)
  })

  servers.forEach((server) => {
    ctx.command(`${server.command} <command:text>`)
      .action(async (_, inputCommand) => {
        const conn = new HLLConnection()
        try {
          await conn.connect(server.host, server.port, server.password)
          
          // 替换自定义指令
          const [firstWord, ...rest] = inputCommand.split(' ')
          const mappedCommand = commandMap.get(firstWord) || firstWord
          const finalCommand = [mappedCommand, ...rest].join(' ')

          conn.send(finalCommand)
          const response = await conn.receive()
          return `[HLL] ${server.name} 响应：\n${response.toString()}`
        } catch (error) {
          return `[HLL] 错误：${error.message}`
        } finally {
          conn.close()
        }
      })
  })
}