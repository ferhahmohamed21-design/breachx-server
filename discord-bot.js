const { Client, GatewayIntentBits, SlashCommandBuilder, REST, Routes, EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const crypto = require('crypto');

let turso = null;
let isBotActive = () => true;
const userCooldowns = new Map();
const messageTracker = new Map();

function setTurso(client) {
    turso = client;
}

function setBotActiveGetter(fn) {
    isBotActive = fn;
}

function generateKeyCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 4; i++) code += chars[Math.floor(Math.random() * chars.length)];
    return code;
}

function isValidKey(key) {
    return /^BreachX-Safe-OB54-[A-Z0-9]{4}-$/.test(key);
}

const GOLD = 0xFFD700;
const RED = 0xFF4444;
const GREEN = 0x44FF66;
const GRAY = 0x888888;

function createEmbed(title, description, color) {
    return new EmbedBuilder()
        .setTitle(title)
        .setDescription(description)
        .setColor(color)
        .setTimestamp();
}

async function deployCommands(clientId, token, guildId) {
    const commands = [];

    const rest = new REST({ version: '10' }).setToken(token);
    try {
        console.log('[BOT] Deploying slash commands...');
        if (guildId) {
            await rest.put(Routes.applicationGuildCommands(clientId, guildId), { body: commands.map(c => c.toJSON()) });
            console.log('[BOT] Guild commands deployed to ' + guildId);
        } else {
            await rest.put(Routes.applicationCommands(clientId), { body: commands.map(c => c.toJSON()) });
            console.log('[BOT] Global commands deployed');
        }

        // Also clear global commands if using guild mode
        if (guildId) {
            await rest.put(Routes.applicationCommands(clientId), { body: [] });
            console.log('[BOT] Global commands cleared');
        }

        console.log('[BOT] Slash commands deployed!');
    } catch (err) {
        console.error('[BOT] Failed to deploy commands:', err.message);
    }
}

function startBot() {
    const TOKEN = process.env.DISCORD_TOKEN;
    const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
    const GUILD_ID = process.env.DISCORD_GUILD_ID || '';

    if (!TOKEN || !CLIENT_ID) {
        console.log('[BOT] DISCORD_TOKEN or DISCORD_CLIENT_ID not set — bot disabled');
        return;
    }

    const client = new Client({
        intents: [
            GatewayIntentBits.Guilds,
            GatewayIntentBits.GuildMessages,
            GatewayIntentBits.MessageContent,
            GatewayIntentBits.GuildMembers
        ]
    });

    client.once('ready', async () => {
        console.log('[BOT] Logged in as ' + client.user.tag);
        await deployCommands(CLIENT_ID, TOKEN, GUILD_ID);
    });

    client.on('interactionCreate', async (interaction) => {
        if (!interaction.isChatInputCommand()) return;
        if (!turso) {
            await interaction.reply({ embeds: [createEmbed('Error', 'Database not connected', RED)], ephemeral: true });
            return;
        }

        const { commandName } = interaction;

        try {
        } catch (err) {
            console.error('[BOT] Error:', err.message);
            const reply = { embeds: [createEmbed('Error', 'Something went wrong: ' + err.message, RED)], ephemeral: true };
            if (interaction.replied || interaction.deferred) {
                await interaction.followUp(reply);
            } else {
                await interaction.reply(reply);
            }
        }
    });

    client.on('messageCreate', async (message) => {
        if (message.author.bot) return;
        if (!message.guild) return;

        const userId = message.author.id;
        const now = Date.now();
        const window = 5000;
        const maxMessages = 3;
        const timeoutDuration = 60000;

        if (!messageTracker.has(userId)) {
            messageTracker.set(userId, []);
        }

        const timestamps = messageTracker.get(userId).filter(t => now - t < window);
        timestamps.push(now);
        messageTracker.set(userId, timestamps);

        if (timestamps.length >= maxMessages) {
            try {
                const member = await message.guild.members.fetch(userId);
                if (member && member.moderatable) {
                    await member.timeout(timeoutDuration, 'Spam detected - 3 messages in 5 seconds');
                    const embed = createEmbed('Timeout', message.author.tag + ' has been timed out for **1 minute** due to spam.', RED);
                    await message.channel.send({ embeds: [embed] });
                    await message.delete().catch(() => {});
                }
            } catch (err) {
                console.log('[BOT] Could not timeout user:', err.message);
            }
            messageTracker.delete(userId);
        }
    });

    client.login(TOKEN).catch(err => {
        console.error('[BOT] Login failed:', err.message);
    });

    return client;
}

module.exports = { startBot, setTurso, setBotActiveGetter };
