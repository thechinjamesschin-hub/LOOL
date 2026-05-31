"""
╔══════════════════════════════════════════════════╗
║          DIGIT — Discord Security Bot            ║
║   Anti-Nuke | Anti-Raid | Moderation | Fun      ║
║                Version 3.0.0                     ║
╚══════════════════════════════════════════════════╝
"""

import discord
from discord.ext import commands
import asyncio
import json
import os
import random
import time
from datetime import datetime, timedelta, timezone
from collections import defaultdict

# ═══════════════════════════════════════════════════
#  CONFIGURATION — Adjust these to your liking
# ═══════════════════════════════════════════════════

BOT_NAME    = "Digit"
BOT_VERSION = "3.0.0"
PREFIX      = "!"

# Anti-Nuke thresholds: (count, seconds)
THRESHOLDS = {
    "ban":            (3, 10),
    "kick":           (3, 10),
    "channel_delete": (3, 10),
    "channel_create": (5, 10),
    "role_delete":    (3, 10),
    "role_create":    (5, 10),
    "webhook_create": (3, 10),
}

# Anti-Raid
RAID_JOIN_THRESHOLD = 10   # accounts joining ...
RAID_JOIN_WINDOW    = 30   # ... within this many seconds

# Anti-Spam
SPAM_MSG_THRESHOLD  = 5    # messages ...
SPAM_MSG_WINDOW     = 3    # ... within this many seconds
MENTION_LIMIT       = 5    # max @mentions in one message
DEFAULT_MIN_AGE     = 7    # minimum account age (days) to join

# ═══════════════════════════════════════════════════
#  GLOBAL STATE
# ═══════════════════════════════════════════════════

# {user_id: {action_key: [timestamps]}}
_action_tracker: dict = defaultdict(lambda: defaultdict(list))

# {guild_id: [timestamps]} — tracks join timestamps for raid detection
_raid_tracker: dict = defaultdict(list)

# {user_id: [timestamps]} — tracks message timestamps for spam detection
_spam_tracker: dict = defaultdict(list)

# {user_id: int} — warning counts
_warnings: dict = defaultdict(int)

# Set of user IDs immune to anti-nuke triggers
_whitelist: set = set()

# Per-guild settings (persisted to config.json)
_guild_config: dict = {}


# ─── Config helpers ────────────────────────────────

def load_config() -> dict:
    global _guild_config
    if os.path.exists("config.json"):
        try:
            with open("config.json", "r") as f:
                content = f.read().strip()
                if content:
                    _guild_config = json.loads(content)
                else:
                    _guild_config = {}
        except (json.JSONDecodeError, ValueError) as e:
            print(f"[WARN] config.json is malformed and will be reset: {e}")
            _guild_config = {}
            # Back up the broken file so the user doesn't lose it
            import shutil
            shutil.copy("config.json", "config.json.bak")
            save_config()
    return _guild_config


def save_config():
    with open("config.json", "w") as f:
        json.dump(_guild_config, f, indent=2)


def get_cfg(guild_id: int) -> dict:
    load_config()
    return _guild_config.get(str(guild_id), {})


def set_cfg(guild_id: int, key: str, value):
    load_config()
    gid = str(guild_id)
    if gid not in _guild_config:
        _guild_config[gid] = {}
    _guild_config[gid][key] = value
    save_config()


# ═══════════════════════════════════════════════════
#  PROTECTION UTILITIES
# ═══════════════════════════════════════════════════

def exceeds_threshold(user_id: int, action: str) -> bool:
    """Return True if the user has triggered this action ≥ threshold times."""
    count, window = THRESHOLDS.get(action, (3, 10))
    now  = time.time()
    log  = _action_tracker[user_id][action]
    log[:] = [t for t in log if now - t < window]
    log.append(now)
    return len(log) >= count


async def send_log(guild: discord.Guild, embed: discord.Embed):
    """Post an embed to the configured log channel (silently fails if unset)."""
    cfg = get_cfg(guild.id)
    ch_id = cfg.get("log_channel")
    if ch_id:
        ch = guild.get_channel(int(ch_id))
        if ch:
            try:
                await ch.send(embed=embed)
            except Exception:
                pass


async def punish_nuker(
    guild: discord.Guild,
    user:  discord.Member | discord.User,
    reason: str,
):
    """
    Full punishment pipeline for a detected nuker/raider:
      1. DM them "Nice try."
      2. Strip all dangerous roles
      3. Ban them from the server
    """
    if user is None:
        return

    # 1 ── DM "Nice try."
    try:
        dm = discord.Embed(
            title="🛡️ Digit Security",
            description=(
                "**Nice try.** 😄\n\n"
                "You've been detected attempting to nuke or raid this server.\n"
                "Everything has been logged and you've been punished.\n"
                "Better luck never! 👋"
            ),
            color=0xFF0000,
        )
        dm.add_field(name="Server",  value=guild.name,                       inline=True)
        dm.add_field(name="Reason",  value=reason,                           inline=True)
        dm.add_field(name="Time",    value=f"<t:{int(time.time())}:F>",      inline=False)
        dm.set_footer(text=f"Powered by {BOT_NAME} v{BOT_VERSION}")
        await user.send(embed=dm)
    except discord.HTTPException:
        pass

    # 2 ── Strip dangerous roles (if they're still a Member)
    DANGEROUS = {
        "administrator", "ban_members", "kick_members",
        "manage_channels", "manage_guild", "manage_roles",
        "manage_webhooks", "manage_messages", "mention_everyone",
    }
    if isinstance(user, discord.Member):
        to_remove = [
            r for r in user.roles[1:]
            if any(getattr(r.permissions, p, False) for p in DANGEROUS)
        ]
        if to_remove:
            try:
                await user.remove_roles(*to_remove, reason=f"[{BOT_NAME}] Anti-Nuke: {reason}")
            except Exception:
                pass

    # 3 ── Ban
    try:
        await guild.ban(
            user,
            reason=f"[{BOT_NAME}] Anti-Nuke: {reason}",
            delete_message_days=1,
        )
    except Exception:
        pass


async def lockdown_all(guild: discord.Guild, lock: bool):
    """Lock or unlock every text channel for @everyone."""
    for ch in guild.channels:
        if not isinstance(ch, (discord.TextChannel, discord.ForumChannel)):
            continue
        try:
            ow = ch.overwrites_for(guild.default_role)
            ow.send_messages = False if lock else None
            reason = (
                f"[{BOT_NAME}] Auto-lockdown — raid detected"
                if lock else
                f"[{BOT_NAME}] Lockdown lifted"
            )
            await ch.set_permissions(guild.default_role, overwrite=ow, reason=reason)
        except Exception:
            pass


# ═══════════════════════════════════════════════════
#  BOT SETUP
# ═══════════════════════════════════════════════════

intents = discord.Intents.all()
bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)
load_config()


# ═══════════════════════════════════════════════════
#  CORE EVENTS
# ═══════════════════════════════════════════════════

@bot.event
async def on_ready():
    banner = f"""
╔══════════════════════════════════════════════════╗
║       {BOT_NAME} Bot v{BOT_VERSION} — ONLINE! 🛡️         ║
║  Protecting servers harder than any bot alive.  ║
╚══════════════════════════════════════════════════╝
  Logged in as : {bot.user} ({bot.user.id})
  Servers      : {len(bot.guilds)}
"""
    print(banner)
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name=f"over your server 🛡️ | {PREFIX}help",
        ),
        status=discord.Status.online,
    )
    try:
        synced = await bot.tree.sync()
        print(f"  Slash commands synced: {len(synced)}")
    except Exception as e:
        print(f"  Slash sync error: {e}")


@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("❌ You don't have permission for that!", delete_after=5)
    elif isinstance(error, commands.MemberNotFound):
        await ctx.send("❌ Member not found.", delete_after=5)
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❌ Missing argument. Try `{PREFIX}help` for usage.", delete_after=5)
    elif isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"⏰ Cooldown! Retry in `{error.retry_after:.1f}s`.", delete_after=5)
    elif isinstance(error, commands.CommandNotFound):
        pass  # silently ignore unknown commands
    elif isinstance(error, commands.BadArgument):
        await ctx.send("❌ Invalid argument.", delete_after=5)
    else:
        print(f"[ERROR] {ctx.command}: {error}")


# ═══════════════════════════════════════════════════
#  ANTI-NUKE — Audit Log Monitoring
# ═══════════════════════════════════════════════════

@bot.event
async def on_audit_log_entry_create(entry: discord.AuditLogEntry):
    guild  = entry.guild
    user   = entry.user
    action = entry.action

    # Ignore the bot itself and whitelisted users
    if user is None or user.id == bot.user.id:
        return
    if user.id in _whitelist:
        return
    if not get_cfg(guild.id).get("antinuke_enabled", True):
        return

    # Helper: build a standard alert embed
    def alert(title: str, description: str) -> discord.Embed:
        e = discord.Embed(
            title=title,
            description=description,
            color=0xFF0000,
            timestamp=datetime.now(timezone.utc),
        )
        e.set_footer(text=f"{BOT_NAME} Anti-Nuke • v{BOT_VERSION}")
        return e

    async def handle(action_key: str, title: str, reason: str):
        if exceeds_threshold(user.id, action_key):
            member = guild.get_member(user.id)
            embed  = alert(
                f"🚨 ANTI-NUKE TRIGGERED: {title}",
                f"**{user}** (`{user.id}`) exceeded the **{action_key.replace('_',' ')}** threshold!\n"
                f"Action taken: **Ban + Role Strip + DM sent**",
            )
            await send_log(guild, embed)
            await punish_nuker(guild, member or user, reason)

    # ── Map audit actions to handlers ──────────────
    if   action == discord.AuditLogAction.ban:
        await handle("ban",            "Mass Ban",            "Mass-banning server members")
    elif action == discord.AuditLogAction.kick:
        await handle("kick",           "Mass Kick",           "Mass-kicking server members")
    elif action == discord.AuditLogAction.channel_delete:
        await handle("channel_delete", "Mass Channel Delete", "Mass-deleting channels")
    elif action == discord.AuditLogAction.channel_create:
        await handle("channel_create", "Mass Channel Create", "Mass-creating channels (nuke attempt)")
    elif action == discord.AuditLogAction.role_delete:
        await handle("role_delete",    "Mass Role Delete",    "Mass-deleting roles")
    elif action == discord.AuditLogAction.role_create:
        await handle("role_create",    "Mass Role Create",    "Mass-creating roles")
    elif action == discord.AuditLogAction.webhook_create:
        await handle("webhook_create", "Webhook Abuse",       "Webhook abuse / token-grab attempt")

    # ── Special: admin perm escalation ─────────────
    elif action == discord.AuditLogAction.role_update:
        after_perms = getattr(getattr(entry.changes, "after", None), "permissions", None)
        if after_perms and after_perms.administrator:
            embed = discord.Embed(
                title="⚠️ ALERT: Administrator Permission Added to Role",
                description=(
                    f"**{user}** gave **Administrator** to a role!\n"
                    f"Role: {entry.target}\n"
                    f"Review this immediately."
                ),
                color=0xFF8C00,
                timestamp=datetime.now(timezone.utc),
            )
            await send_log(guild, embed)

    # ── Special: mass member prune ──────────────────
    elif action == discord.AuditLogAction.member_prune:
        member = guild.get_member(user.id)
        embed  = discord.Embed(
            title="🚨 ANTI-NUKE TRIGGERED: Mass Member Prune",
            description=f"**{user}** (`{user.id}`) performed a mass member prune!",
            color=0xFF0000,
            timestamp=datetime.now(timezone.utc),
        )
        await send_log(guild, embed)
        await punish_nuker(guild, member or user, "Mass member prune")

    # ── Log: bot added ──────────────────────────────
    elif action == discord.AuditLogAction.bot_add:
        embed = discord.Embed(
            title="🤖 New Bot Added",
            description=f"**{user}** added a bot to the server.",
            color=0x3498DB,
            timestamp=datetime.now(timezone.utc),
        )
        if entry.target:
            embed.add_field(name="Bot", value=f"{entry.target} (`{entry.target.id}`)", inline=True)
        await send_log(guild, embed)

    # ── Log: guild settings changed ─────────────────
    elif action == discord.AuditLogAction.guild_update:
        embed = discord.Embed(
            title="⚙️ Server Settings Changed",
            description=f"**{user}** modified server settings.",
            color=0xF39C12,
            timestamp=datetime.now(timezone.utc),
        )
        await send_log(guild, embed)


# ═══════════════════════════════════════════════════
#  ANTI-RAID — Member Join Detection
# ═══════════════════════════════════════════════════

@bot.event
async def on_member_join(member: discord.Member):
    guild = member.guild
    cfg   = get_cfg(guild.id)

    if not cfg.get("antiraid_enabled", True):
        return

    now = time.time()

    # ── Raid detection ──────────────────────────────
    _raid_tracker[guild.id] = [
        t for t in _raid_tracker[guild.id]
        if now - t < RAID_JOIN_WINDOW
    ]
    _raid_tracker[guild.id].append(now)

    if len(_raid_tracker[guild.id]) >= RAID_JOIN_THRESHOLD:
        _raid_tracker[guild.id].clear()
        embed = discord.Embed(
            title="🚨 RAID DETECTED — AUTO-LOCKDOWN ACTIVE",
            description=(
                f"**{RAID_JOIN_THRESHOLD}+ accounts** joined within **{RAID_JOIN_WINDOW}s**!\n"
                f"All channels are now **locked**.\n"
                f"Run `{PREFIX}unlock` once the coast is clear."
            ),
            color=0xFF0000,
            timestamp=datetime.now(timezone.utc),
        )
        await send_log(guild, embed)
        await lockdown_all(guild, lock=True)
        return

    # ── New account age check ───────────────────────
    min_age    = cfg.get("min_account_age", DEFAULT_MIN_AGE)
    account_age = (datetime.now(timezone.utc) - member.created_at).days

    if account_age < min_age:
        try:
            dm = discord.Embed(
                title=f"❌ Access Denied — {guild.name}",
                description=(
                    f"Your account is only **{account_age} day(s)** old.\n"
                    f"Minimum required: **{min_age} days**.\n"
                    f"Please try again in **{min_age - account_age} day(s)**."
                ),
                color=0xFF8C00,
            )
            dm.set_footer(text=f"Protected by {BOT_NAME}")
            await member.send(embed=dm)
        except Exception:
            pass

        try:
            await member.kick(
                reason=f"[{BOT_NAME}] Account too new ({account_age}d < {min_age}d)"
            )
        except Exception:
            pass

        log_embed = discord.Embed(
            title="🔒 New Account Rejected",
            description=f"**{member}** (`{member.id}`) kicked — account too new.",
            color=0xFF8C00,
        )
        log_embed.add_field(name="Account Age", value=f"{account_age} days",  inline=True)
        log_embed.add_field(name="Required",    value=f"{min_age} days",      inline=True)
        await send_log(guild, log_embed)


@bot.event
async def on_member_remove(member: discord.Member):
    embed = discord.Embed(
        title="👋 Member Left",
        description=f"**{member}** (`{member.id}`) left the server.",
        color=0x95A5A6,
        timestamp=datetime.now(timezone.utc),
    )
    embed.set_thumbnail(url=member.display_avatar.url)
    await send_log(member.guild, embed)


# ═══════════════════════════════════════════════════
#  ANTI-SPAM — Message Monitoring
# ═══════════════════════════════════════════════════

@bot.event
async def on_message(message: discord.Message):
    # Skip DMs, bots, and whitelisted users
    if not message.guild or message.author.bot:
        await bot.process_commands(message)
        return
    if message.author.id in _whitelist:
        await bot.process_commands(message)
        return
    if not get_cfg(message.guild.id).get("antispam_enabled", True):
        await bot.process_commands(message)
        return

    now = time.time()
    uid = message.author.id

    # ── Message spam ───────────────────────────────
    _spam_tracker[uid] = [t for t in _spam_tracker[uid] if now - t < SPAM_MSG_WINDOW]
    _spam_tracker[uid].append(now)

    if len(_spam_tracker[uid]) >= SPAM_MSG_THRESHOLD:
        _spam_tracker[uid].clear()
        try:
            until = datetime.now(timezone.utc) + timedelta(minutes=10)
            await message.author.timeout(until, reason=f"[{BOT_NAME}] Spam detected")
            await message.channel.purge(
                limit=20, check=lambda m: m.author == message.author
            )
            await message.channel.send(
                f"🛡️ {message.author.mention} has been timed out **10 minutes** for spamming.",
                delete_after=10,
            )
        except Exception:
            pass
        log_embed = discord.Embed(
            title="🚫 Spam — Auto-Timeout",
            description=f"**{message.author}** timed out 10min for message spam.",
            color=0xFF8C00,
        )
        await send_log(message.guild, log_embed)
        return

    # ── Mass mention ───────────────────────────────
    if len(message.mentions) >= MENTION_LIMIT:
        try:
            await message.delete()
            until = datetime.now(timezone.utc) + timedelta(minutes=30)
            await message.author.timeout(until, reason=f"[{BOT_NAME}] Mass mention")
            await message.channel.send(
                f"🛡️ {message.author.mention} timed out **30 minutes** for mass-mentioning.",
                delete_after=10,
            )
        except Exception:
            pass
        log_embed = discord.Embed(
            title="🚫 Mass Mention — Auto-Timeout",
            description=(
                f"**{message.author}** used {len(message.mentions)} mentions.\n"
                f"Message deleted. User timed out 30 minutes."
            ),
            color=0xFF8C00,
        )
        await send_log(message.guild, log_embed)
        return

    # ── Invite link filter ─────────────────────────
    if any(k in message.content for k in ("discord.gg/", "discord.com/invite/")):
        if not message.author.guild_permissions.manage_messages:
            try:
                await message.delete()
                await message.channel.send(
                    f"🚫 {message.author.mention} Invite links aren't allowed here!",
                    delete_after=5,
                )
            except Exception:
                pass
            return

    await bot.process_commands(message)


# ═══════════════════════════════════════════════════
#  MODERATION COMMANDS
# ═══════════════════════════════════════════════════

@bot.command(name="ban")
@commands.has_permissions(ban_members=True)
async def ban_cmd(ctx, member: discord.Member, *, reason="No reason provided"):
    if member.top_role >= ctx.author.top_role:
        return await ctx.send("❌ Can't ban someone with an equal or higher role!", delete_after=5)
    try:
        await member.send(f"You've been **banned** from **{ctx.guild.name}**.\nReason: {reason}")
    except Exception:
        pass
    await member.ban(reason=reason, delete_message_days=1)
    embed = discord.Embed(title="🔨 Banned", description=f"**{member}** has been banned.", color=discord.Color.red())
    embed.add_field(name="Reason", value=reason)
    embed.add_field(name="By", value=ctx.author.mention)
    await ctx.send(embed=embed)
    await send_log(ctx.guild, embed)


@bot.command(name="unban")
@commands.has_permissions(ban_members=True)
async def unban_cmd(ctx, *, user_id: int):
    try:
        user = await bot.fetch_user(user_id)
        await ctx.guild.unban(user, reason=f"Unbanned by {ctx.author}")
        await ctx.send(f"✅ **{user}** has been unbanned.")
    except discord.NotFound:
        await ctx.send("❌ That user isn't banned or doesn't exist.")


@bot.command(name="kick")
@commands.has_permissions(kick_members=True)
async def kick_cmd(ctx, member: discord.Member, *, reason="No reason provided"):
    if member.top_role >= ctx.author.top_role:
        return await ctx.send("❌ Can't kick someone with an equal or higher role!", delete_after=5)
    await member.kick(reason=reason)
    embed = discord.Embed(title="👟 Kicked", description=f"**{member}** has been kicked.", color=discord.Color.orange())
    embed.add_field(name="Reason", value=reason)
    embed.add_field(name="By", value=ctx.author.mention)
    await ctx.send(embed=embed)
    await send_log(ctx.guild, embed)


@bot.command(name="mute")
@commands.has_permissions(moderate_members=True)
async def mute_cmd(ctx, member: discord.Member, duration: int = 10, *, reason="No reason"):
    until = datetime.now(timezone.utc) + timedelta(minutes=duration)
    await member.timeout(until, reason=reason)
    embed = discord.Embed(
        title="🔇 Muted",
        description=f"**{member}** timed out **{duration} min**.\nReason: {reason}",
        color=discord.Color.orange(),
    )
    await ctx.send(embed=embed)


@bot.command(name="unmute")
@commands.has_permissions(moderate_members=True)
async def unmute_cmd(ctx, member: discord.Member):
    await member.timeout(None)
    await ctx.send(f"🔊 **{member}** has been unmuted.")


@bot.command(name="warn")
@commands.has_permissions(manage_messages=True)
async def warn_cmd(ctx, member: discord.Member, *, reason="No reason provided"):
    _warnings[member.id] += 1
    count = _warnings[member.id]
    embed = discord.Embed(
        title="⚠️ Member Warned",
        description=f"**{member}** has been warned. `{count}/3`",
        color=discord.Color.yellow(),
    )
    embed.add_field(name="Reason", value=reason)
    embed.add_field(name="By", value=ctx.author.mention)
    await ctx.send(embed=embed)
    try:
        await member.send(
            f"⚠️ You've been warned in **{ctx.guild.name}**.\nReason: {reason}\nTotal warnings: {count}/3"
        )
    except Exception:
        pass
    if count >= 3:
        await ctx.send(f"🚨 **{member}** has hit **3 warnings**! Take action.")


@bot.command(name="warnings")
@commands.has_permissions(manage_messages=True)
async def warnings_cmd(ctx, member: discord.Member):
    count = _warnings.get(member.id, 0)
    embed = discord.Embed(
        title=f"⚠️ Warnings — {member}",
        description=f"**{count}** warning(s) on record.",
        color=discord.Color.yellow(),
    )
    await ctx.send(embed=embed)


@bot.command(name="clearwarns")
@commands.has_permissions(administrator=True)
async def clearwarns_cmd(ctx, member: discord.Member):
    _warnings[member.id] = 0
    await ctx.send(f"✅ Cleared all warnings for **{member}**.")


@bot.command(name="purge", aliases=["clear"])
@commands.has_permissions(manage_messages=True)
async def purge_cmd(ctx, amount: int = 5):
    amount = min(amount, 100)
    await ctx.channel.purge(limit=amount + 1)
    msg = await ctx.send(f"🗑️ Deleted **{amount}** messages.")
    await asyncio.sleep(3)
    try:
        await msg.delete()
    except Exception:
        pass


@bot.command(name="slowmode")
@commands.has_permissions(manage_channels=True)
async def slowmode_cmd(ctx, seconds: int = 0):
    await ctx.channel.edit(slowmode_delay=seconds)
    await ctx.send(
        f"✅ Slowmode **disabled**." if seconds == 0 else f"✅ Slowmode set to **{seconds}s**."
    )


@bot.command(name="nick")
@commands.has_permissions(manage_nicknames=True)
async def nick_cmd(ctx, member: discord.Member, *, nickname=None):
    old = member.display_name
    await member.edit(nick=nickname)
    await ctx.send(f"✅ Changed **{old}**'s nick to **{nickname or member.name}**.")


@bot.command(name="lockdown")
@commands.has_permissions(administrator=True)
async def lockdown_cmd(ctx):
    await lockdown_all(ctx.guild, lock=True)
    embed = discord.Embed(
        title="🔒 SERVER LOCKED DOWN",
        description=f"All channels locked!\nUse `{PREFIX}unlock` to lift.",
        color=discord.Color.red(),
    )
    await ctx.send(embed=embed)


@bot.command(name="unlock")
@commands.has_permissions(administrator=True)
async def unlock_cmd(ctx):
    await lockdown_all(ctx.guild, lock=False)
    embed = discord.Embed(
        title="🔓 Lockdown Lifted",
        description="Members can send messages again. Stay vigilant!",
        color=discord.Color.green(),
    )
    await ctx.send(embed=embed)


# ═══════════════════════════════════════════════════
#  SETUP & CONFIGURATION COMMANDS
# ═══════════════════════════════════════════════════

@bot.command(name="setup")
@commands.has_permissions(administrator=True)
async def setup_cmd(ctx, channel: discord.TextChannel = None):
    target = channel or ctx.channel
    set_cfg(ctx.guild.id, "log_channel",      target.id)
    set_cfg(ctx.guild.id, "antinuke_enabled", True)
    set_cfg(ctx.guild.id, "antiraid_enabled", True)
    set_cfg(ctx.guild.id, "antispam_enabled", True)
    set_cfg(ctx.guild.id, "min_account_age",  DEFAULT_MIN_AGE)

    embed = discord.Embed(
        title=f"✅ {BOT_NAME} Setup Complete!",
        description=f"Log channel → {target.mention}\nAll protection modules are now **ACTIVE**.",
        color=discord.Color.green(),
    )
    embed.add_field(name="🛡️ Anti-Nuke",  value="✅ Enabled", inline=True)
    embed.add_field(name="🚨 Anti-Raid",   value="✅ Enabled", inline=True)
    embed.add_field(name="🚫 Anti-Spam",   value="✅ Enabled", inline=True)
    embed.set_footer(text=f"{BOT_NAME} v{BOT_VERSION}")
    await ctx.send(embed=embed)


@bot.command(name="whitelist")
@commands.has_permissions(administrator=True)
async def whitelist_cmd(ctx, member: discord.Member):
    _whitelist.add(member.id)
    await ctx.send(f"✅ **{member}** is now whitelisted — immune to anti-nuke triggers.")


@bot.command(name="unwhitelist")
@commands.has_permissions(administrator=True)
async def unwhitelist_cmd(ctx, member: discord.Member):
    _whitelist.discard(member.id)
    await ctx.send(f"✅ **{member}** removed from whitelist.")


@bot.command(name="antinuke")
@commands.has_permissions(administrator=True)
async def antinuke_cmd(ctx, state: str = "status"):
    s = state.lower()
    if s == "on":
        set_cfg(ctx.guild.id, "antinuke_enabled", True)
        await ctx.send("✅ Anti-Nuke **ENABLED**.")
    elif s == "off":
        set_cfg(ctx.guild.id, "antinuke_enabled", False)
        await ctx.send("⚠️ Anti-Nuke **DISABLED** — your server is now vulnerable!")
    else:
        enabled = get_cfg(ctx.guild.id).get("antinuke_enabled", True)
        await ctx.send(f"🛡️ Anti-Nuke is **{'ENABLED ✅' if enabled else 'DISABLED ❌'}**.")


@bot.command(name="antiraid")
@commands.has_permissions(administrator=True)
async def antiraid_cmd(ctx, state: str = "status"):
    s = state.lower()
    if s == "on":
        set_cfg(ctx.guild.id, "antiraid_enabled", True)
        await ctx.send("✅ Anti-Raid **ENABLED**.")
    elif s == "off":
        set_cfg(ctx.guild.id, "antiraid_enabled", False)
        await ctx.send("⚠️ Anti-Raid **DISABLED**.")
    else:
        enabled = get_cfg(ctx.guild.id).get("antiraid_enabled", True)
        await ctx.send(f"🚨 Anti-Raid is **{'ENABLED ✅' if enabled else 'DISABLED ❌'}**.")


@bot.command(name="antispam")
@commands.has_permissions(administrator=True)
async def antispam_cmd(ctx, state: str = "status"):
    s = state.lower()
    if s == "on":
        set_cfg(ctx.guild.id, "antispam_enabled", True)
        await ctx.send("✅ Anti-Spam **ENABLED**.")
    elif s == "off":
        set_cfg(ctx.guild.id, "antispam_enabled", False)
        await ctx.send("⚠️ Anti-Spam **DISABLED**.")
    else:
        enabled = get_cfg(ctx.guild.id).get("antispam_enabled", True)
        await ctx.send(f"🚫 Anti-Spam is **{'ENABLED ✅' if enabled else 'DISABLED ❌'}**.")


@bot.command(name="setage")
@commands.has_permissions(administrator=True)
async def setage_cmd(ctx, days: int):
    """Set minimum account age (in days) required to join."""
    set_cfg(ctx.guild.id, "min_account_age", max(0, days))
    await ctx.send(f"✅ Minimum account age set to **{days} day(s)**.")


@bot.command(name="status")
@commands.has_permissions(manage_guild=True)
async def status_cmd(ctx):
    cfg    = get_cfg(ctx.guild.id)
    log_ch = cfg.get("log_channel")
    ms     = round(bot.latency * 1000)

    embed = discord.Embed(
        title=f"🛡️ {BOT_NAME} — Security Dashboard",
        description=f"Protection overview for **{ctx.guild.name}**",
        color=discord.Color.blurple(),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(name="🛡️ Anti-Nuke",  value="✅" if cfg.get("antinuke_enabled", True) else "❌", inline=True)
    embed.add_field(name="🚨 Anti-Raid",   value="✅" if cfg.get("antiraid_enabled", True) else "❌", inline=True)
    embed.add_field(name="🚫 Anti-Spam",   value="✅" if cfg.get("antispam_enabled", True) else "❌", inline=True)
    embed.add_field(name="📝 Log Channel", value=f"<#{log_ch}>" if log_ch else "Not set",            inline=True)
    embed.add_field(name="🏳️ Whitelisted", value=str(len(_whitelist)),                               inline=True)
    embed.add_field(name="⚡ Latency",     value=f"{ms}ms",                                           inline=True)
    embed.add_field(name="🔞 Min Acc Age", value=f"{cfg.get('min_account_age', DEFAULT_MIN_AGE)}d",  inline=True)

    embed.add_field(
        name="📊 Thresholds",
        value=(
            f"**Ban / Kick / Role Del:**  {THRESHOLDS['ban'][0]} in {THRESHOLDS['ban'][1]}s\n"
            f"**Ch. Delete:**             {THRESHOLDS['channel_delete'][0]} in {THRESHOLDS['channel_delete'][1]}s\n"
            f"**Ch. Create:**             {THRESHOLDS['channel_create'][0]} in {THRESHOLDS['channel_create'][1]}s\n"
            f"**Raid Joins:**             {RAID_JOIN_THRESHOLD} in {RAID_JOIN_WINDOW}s\n"
            f"**Spam Msgs:**              {SPAM_MSG_THRESHOLD} in {SPAM_MSG_WINDOW}s\n"
            f"**Max Mentions:**           {MENTION_LIMIT} per message"
        ),
        inline=False,
    )
    embed.set_footer(text=f"{BOT_NAME} v{BOT_VERSION} — Stronger than every other bot 💪")
    await ctx.send(embed=embed)


# ═══════════════════════════════════════════════════
#  INFO COMMANDS
# ═══════════════════════════════════════════════════

@bot.command(name="ping")
async def ping_cmd(ctx):
    ms    = round(bot.latency * 1000)
    color = discord.Color.green() if ms < 100 else discord.Color.orange() if ms < 200 else discord.Color.red()
    await ctx.send(embed=discord.Embed(title="🏓 Pong!", description=f"**{ms}ms**", color=color))


@bot.command(name="serverinfo")
async def serverinfo_cmd(ctx):
    g = ctx.guild
    embed = discord.Embed(title=f"📊 {g.name}", color=discord.Color.blurple(), timestamp=datetime.now(timezone.utc))
    if g.icon:
        embed.set_thumbnail(url=g.icon.url)
    embed.add_field(name="👑 Owner",      value=g.owner.mention if g.owner else "?", inline=True)
    embed.add_field(name="👥 Members",    value=g.member_count,                       inline=True)
    embed.add_field(name="💬 Channels",   value=len(g.channels),                      inline=True)
    embed.add_field(name="🎭 Roles",      value=len(g.roles),                         inline=True)
    embed.add_field(name="📅 Created",    value=f"<t:{int(g.created_at.timestamp())}:R>", inline=True)
    embed.add_field(name="🔐 2FA",        value="Required" if g.mfa_level else "No",  inline=True)
    embed.set_footer(text=f"ID: {g.id} • {BOT_NAME}")
    await ctx.send(embed=embed)


@bot.command(name="userinfo", aliases=["whois"])
async def userinfo_cmd(ctx, member: discord.Member = None):
    m   = member or ctx.author
    age = (datetime.now(timezone.utc) - m.created_at).days
    embed = discord.Embed(title=f"👤 {m}", color=m.color, timestamp=datetime.now(timezone.utc))
    embed.set_thumbnail(url=m.display_avatar.url)
    embed.add_field(name="🆔 ID",       value=m.id,                                          inline=True)
    embed.add_field(name="📛 Nick",     value=m.display_name,                                inline=True)
    embed.add_field(name="🤖 Bot",      value="Yes" if m.bot else "No",                      inline=True)
    embed.add_field(name="📅 Created",  value=f"<t:{int(m.created_at.timestamp())}:R>",     inline=True)
    embed.add_field(name="📅 Joined",   value=f"<t:{int(m.joined_at.timestamp())}:R>",      inline=True)
    embed.add_field(name="⏰ Age",      value=f"{age} days",                                 inline=True)
    roles = [r.mention for r in m.roles[1:]]
    if roles:
        embed.add_field(name=f"🎭 Roles ({len(roles)})", value=" ".join(roles[:6]) + ("…" if len(roles) > 6 else ""), inline=False)
    embed.add_field(name="⚠️ Warnings", value=_warnings.get(m.id, 0), inline=True)
    embed.set_footer(text=BOT_NAME)
    await ctx.send(embed=embed)


@bot.command(name="avatar", aliases=["av"])
async def avatar_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    embed = discord.Embed(title=f"🖼️ {m.display_name}'s Avatar", color=discord.Color.blurple())
    embed.set_image(url=m.display_avatar.url)
    embed.add_field(
        name="Links",
        value=(
            f"[PNG]({m.display_avatar.replace(format='png').url}) | "
            f"[JPG]({m.display_avatar.replace(format='jpg').url}) | "
            f"[WEBP]({m.display_avatar.replace(format='webp').url})"
        ),
    )
    await ctx.send(embed=embed)


# ═══════════════════════════════════════════════════
#  FUN COMMANDS 😄
# ═══════════════════════════════════════════════════

@bot.command(name="ratio")
async def ratio_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    msgs = [
        f"L + ratio + {m.mention} got deleted from existence. No saves. 💀",
        f"{m.mention} ratio'd into another dimension 📉 Fr fr no cap.",
        f"{m.mention} L + ratio + didn't ask + cope + mald + skill issue 🗿",
        f"The {BOT_NAME} Council has spoken: {m.mention} is **hereby ratio'd**. No appeals. 📜",
        f"{m.mention} touched grass and still got ratio'd. Impressive failure. 🌿",
        f"Breaking news: {m.mention} has been ratio'd harder than a dial-up modem. 📡",
    ]
    await ctx.send(random.choice(msgs))


@bot.command(name="iq")
async def iq_cmd(ctx, member: discord.Member = None):
    m     = member or ctx.author
    score = random.randint(1, 200)
    comment = (
        "🐠 A goldfish called. It wants its brain back."  if score < 50  else
        "📉 You tried. A for effort. F for existence."     if score < 80  else
        "😐 Average. Please breathe through your nose."   if score < 100 else
        "👍 Not bad. You might survive a zombie outbreak." if score < 130 else
        "👑 Impressive. Consider world domination."        if score < 160 else
        "🌌 GALAXY BRAIN. Stop thinking — reality is cracking."
    )
    embed = discord.Embed(
        title=f"🧠 IQ Results — {m.display_name}",
        description=f"**Score: {score} IQ**\n{comment}",
        color=discord.Color.purple(),
    )
    await ctx.send(embed=embed)


@bot.command(name="roast")
@commands.cooldown(1, 10, commands.BucketType.user)
async def roast_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    roasts = [
        f"{m.mention} You're the reason shampoo has instructions.",
        f"{m.mention} I'd agree with you but then we'd both be wrong.",
        f"{m.mention} You're the human version of a 404 error.",
        f"{m.mention} Even your spam folder rejects your emails.",
        f"{m.mention} You're like software updates — nobody wants you but you keep appearing.",
        f"{m.mention} You're proof that evolution occasionally takes a lunch break.",
        f"{m.mention} I've seen better ideas on bathroom walls.",
        f"{m.mention} You're the participation trophy of Discord servers.",
        f"{m.mention} Your WiFi password is probably 'password'. Isn't it. 😂",
        f"{m.mention} Your gaming setup is more impressive than your actual skill. Way more.",
    ]
    await ctx.send(random.choice(roasts))


@bot.command(name="sus")
async def sus_cmd(ctx, member: discord.Member = None):
    m   = member or ctx.author
    lvl = random.randint(0, 100)
    verdict, color = (
        ("You're clean. Probably. 🟢", discord.Color.green())    if lvl < 20 else
        ("A *little* sus... 🟡 Keep watching.",  discord.Color.yellow()) if lvl < 50 else
        ("Very sus. 🟠 Call an emergency meeting.",discord.Color.orange()) if lvl < 80 else
        ("MEGA SUS. 🔴 VOTE THEM OUT NOW!!!",    discord.Color.red())
    )
    embed = discord.Embed(
        title="📮 Sus-O-Meter™",
        description=f"**{m.display_name}** is **{lvl}% sus**\n{verdict}",
        color=color,
    )
    embed.set_footer(text="Digit Sus Detector — Powered by Galaxy Brain AI™")
    await ctx.send(embed=embed)


@bot.command(name="touchgrass", aliases=["grass"])
async def touchgrass_cmd(ctx, member: discord.Member = None):
    m = member or ctx.author
    hours = random.randint(1, 72)
    activities = [
        "touch some grass", "see natural sunlight", "talk to a real human",
        "drink water from a glass (not a can)", "feel wind on your face",
        "remember that trees exist", "pet a dog or something",
    ]
    embed = discord.Embed(
        title="🌿 Official Touch Grass Advisory",
        description=(
            f"{m.mention}, the {BOT_NAME} Wellness Department™ strongly recommends you go "
            f"**{random.choice(activities)}**.\n\n"
            f"Recommended outdoor duration: **{hours} hours**\n"
            f"This is not a suggestion. This is an intervention."
        ),
        color=discord.Color.green(),
    )
    await ctx.send(embed=embed)


@bot.command(name="skill")
async def skill_cmd(ctx, member: discord.Member = None):
    m         = member or ctx.author
    lvl       = random.randint(0, 100)
    skill_name = random.choice([
        "Trolling", "Sleeping 20hrs/day", "Gaming", "Being Delusional",
        "Making Excuses", "Being Chronically Online", "Overthinking",
        "Avoiding Responsibilities", "Speedrunning Life Mistakes",
    ])
    bar     = "█" * (lvl // 10) + "░" * (10 - lvl // 10)
    verdict = (
        "CERTIFIED GOAT 🐐"       if lvl == 100 else
        "Pretty decent ngl 👍"     if lvl > 70  else
        "Mid behavior 😐"          if lvl > 40  else
        "Uninstall and try again 💀"
    )
    embed = discord.Embed(
        title=f"💪 Skill Report — {m.display_name}",
        description=f"**{skill_name}**\n`[{bar}]` {lvl}/100\n\n{verdict}",
        color=discord.Color.gold(),
    )
    await ctx.send(embed=embed)


@bot.command(name="ship")
async def ship_cmd(ctx, m1: discord.Member, m2: discord.Member = None):
    m2    = m2 or ctx.author
    score = random.randint(0, 100)
    bar   = "💕" * (score // 20) + "🖤" * (5 - score // 20)
    verdict = (
        "💔 Absolutely not. Zero chance."           if score < 20 else
        "😬 It's... complicated."                   if score < 40 else
        "🤔 There's potential here."                if score < 60 else
        "💖 Looking good! Ship it!"                 if score < 80 else
        "💘 SOULMATES. Get married already please."
    )
    embed = discord.Embed(
        title="💘 Ship Calculator™",
        description=(
            f"**{m1.display_name}** ❤️ **{m2.display_name}**\n\n"
            f"`[{bar}]` {score}%\n{verdict}"
        ),
        color=discord.Color.red(),
    )
    await ctx.send(embed=embed)


@bot.command(name="coinflip", aliases=["flip"])
async def coinflip_cmd(ctx):
    result = random.choice(["**Heads** 🪙", "**Tails** 🔘"])
    await ctx.send(f"🪙 The coin landed on {result}!")


@bot.command(name="rps")
async def rps_cmd(ctx, choice: str):
    icons = {"rock": "🪨", "paper": "📄", "scissors": "✂️"}
    choice = choice.lower()
    if choice not in icons:
        return await ctx.send("❌ Pick `rock`, `paper`, or `scissors`!")
    bot_pick = random.choice(list(icons.keys()))
    if choice == bot_pick:
        result, color = "It's a **tie!** 🤝",         discord.Color.yellow()
    elif (choice, bot_pick) in [("rock","scissors"), ("paper","rock"), ("scissors","paper")]:
        result, color = "You **win!** 🎉 Lucky...",   discord.Color.green()
    else:
        result, color = "I **win!** 😎 Get good.",    discord.Color.red()
    embed = discord.Embed(
        title="🎮 Rock Paper Scissors",
        description=f"You: {icons[choice]} vs Me: {icons[bot_pick]}\n{result}",
        color=color,
    )
    await ctx.send(embed=embed)


@bot.command(name="8ball", aliases=["ask"])
async def eightball_cmd(ctx, *, question):
    responses = [
        "It is certain. ✅", "Definitely so. ✅", "Without a doubt. ✅",
        "Yes, absolutely. ✅", "Signs point to yes. ✅", "Most likely. ✅",
        "Ask again later. 🔮", "Cannot predict now. 🔮", "Better not tell you. 🔮",
        "My reply is no. ❌", "Don't count on it. ❌", "Very doubtful. ❌",
        "Outlook not good. ❌", "ABSOLUTELY NOT — what were you thinking? 💀",
    ]
    embed = discord.Embed(title="🎱 Magic 8-Ball", color=discord.Color.dark_blue())
    embed.add_field(name="❓ Question", value=question,                  inline=False)
    embed.add_field(name="🎱 Answer",   value=random.choice(responses),  inline=False)
    await ctx.send(embed=embed)


@bot.command(name="hack")
@commands.cooldown(1, 30, commands.BucketType.channel)
async def hack_cmd(ctx, member: discord.Member = None):
    """Totally real hacking simulator (obviously fake 😄)"""
    m   = member or ctx.author
    msg = await ctx.send(f"```ansi\n\u001b[32m[DIGIT] Initiating totally real hack on {m.display_name}...\u001b[0m\n```")
    await asyncio.sleep(1.2)
    await msg.edit(content=f"```ansi\n\u001b[32m[DIGIT] Locating IP: 127.0.0.1\n[DIGIT] Wait... that's literally their own computer 💀\u001b[0m\n```")
    await asyncio.sleep(1.5)
    await msg.edit(content=(
        f"```ansi\n\u001b[32m[DIGIT] Scanning files..."
        f"\n  > 1,457 Discord memes (unorganised)"
        f"\n  > 89 unfinished 'projects'"
        f"\n  > Minecraft screenshots (volume: embarrassing)"
        f"\n  > 3 self-help books at 0% read"
        f"\n  > Search history: 'how to be cool'\u001b[0m\n```"
    ))
    await asyncio.sleep(1.8)
    await msg.edit(content=(
        f"```ansi\n\u001b[31m[DIGIT] HACK COMPLETE."
        f"\n{m.display_name} has been:"
        f"\n  ✓ Ratio'd"
        f"\n  ✓ Exposed"
        f"\n  ✓ L + no-life confirmed"
        f"\nNo actual hacking occurred. Skill issue detected. 🗿\u001b[0m\n```"
    ))


@bot.command(name="brainsize", aliases=["pp"])
async def brainsize_cmd(ctx, member: discord.Member = None):
    m    = member or ctx.author
    size = random.randint(0, 20)
    bar  = "=" * size
    embed = discord.Embed(
        title=f"🧠 Brain Size Meter — {m.display_name}",
        description=f"8{bar}D  {size}cm of pure intelligence",
        color=discord.Color.blue(),
    )
    embed.set_footer(text="This measures brain size. Obviously. 🧠")
    await ctx.send(embed=embed)


@bot.command(name="dice")
async def dice_cmd(ctx, sides: int = 6):
    if sides < 2:
        return await ctx.send("❌ A die needs at least 2 sides!")
    result = random.randint(1, sides)
    await ctx.send(f"🎲 You rolled a **d{sides}** and got: **{result}**!")


@bot.command(name="rate")
async def rate_cmd(ctx, *, thing: str):
    score = random.randint(0, 10)
    embed = discord.Embed(
        title="📊 Digit's Rating",
        description=f"I rate **{thing}** a **{score}/10**.",
        color=discord.Color.gold(),
    )
    if score == 0:
        embed.set_footer(text="Absolutely cooked. Delete it.")
    elif score == 10:
        embed.set_footer(text="Flawless. Frame it.")
    await ctx.send(embed=embed)


# ═══════════════════════════════════════════════════
#  HELP COMMAND
# ═══════════════════════════════════════════════════

@bot.command(name="help")
async def help_cmd(ctx, category: str = None):
    if category is None:
        embed = discord.Embed(
            title=f"🛡️ {BOT_NAME} v{BOT_VERSION} — Help Menu",
            description=(
                f"The **strongest** anti-nuke & anti-raid bot. Period.\n"
                f"Prefix: `{PREFIX}` | Use `{PREFIX}help <category>` for details.\n\n"
                f"**📂 Categories**\n"
                f"🔨 `{PREFIX}help mod` — Moderation\n"
                f"🛡️ `{PREFIX}help protect` — Anti-Nuke & Security\n"
                f"😄 `{PREFIX}help fun` — Fun Commands\n"
                f"ℹ️ `{PREFIX}help info` — Info Commands"
            ),
            color=discord.Color.blurple(),
        )
        embed.add_field(name="🚀 Quick Start", value=f"Run `{PREFIX}setup` to get {BOT_NAME} running!", inline=False)
        embed.set_footer(text=f"{BOT_NAME} v{BOT_VERSION} — Protecting servers like a legend 💪")
        return await ctx.send(embed=embed)

    cat = category.lower()

    if cat in ("mod", "moderation"):
        embed = discord.Embed(title="🔨 Moderation Commands", color=discord.Color.red())
        for cmd, desc in [
            ("ban @user [reason]",          "Permanently ban a member"),
            ("unban <user_id>",             "Unban a member by ID"),
            ("kick @user [reason]",         "Kick a member"),
            ("mute @user [min] [reason]",   "Timeout a member (default 10min)"),
            ("unmute @user",                "Remove timeout"),
            ("warn @user [reason]",         "Warn a member (3 warns = alert)"),
            ("warnings @user",              "Check warning count"),
            ("clearwarns @user",            "Clear all warnings"),
            ("purge [amount]",              "Bulk delete up to 100 messages"),
            ("slowmode [seconds]",          "Set channel slowmode (0 = off)"),
            ("nick @user [name]",           "Change a member's nickname"),
            ("lockdown",                    "Lock all channels"),
            ("unlock",                      "Unlock all channels"),
        ]:
            embed.add_field(name=f"`{PREFIX}{cmd}`", value=desc, inline=False)

    elif cat in ("protect", "protection", "security"):
        embed = discord.Embed(title="🛡️ Protection Commands", color=discord.Color.green())
        for cmd, desc in [
            ("setup [#channel]",            "Set log channel + enable all protection"),
            ("antinuke [on/off/status]",    "Toggle the anti-nuke system"),
            ("antiraid [on/off/status]",    "Toggle the anti-raid system"),
            ("antispam [on/off/status]",    "Toggle the anti-spam system"),
            ("whitelist @user",             "Whitelist a user (immune to auto-punish)"),
            ("unwhitelist @user",           "Remove from whitelist"),
            ("setage <days>",               "Set minimum account age to join"),
            ("status",                      "Full security dashboard"),
        ]:
            embed.add_field(name=f"`{PREFIX}{cmd}`", value=desc, inline=False)
        embed.add_field(
            name="🔒 Auto-Protections (Always Active)",
            value=(
                "• Mass Ban / Kick / Channel Delete+Create / Role Delete+Create\n"
                "• Webhook Abuse & Token-Grab Detection\n"
                "• Admin Permission Escalation Alert\n"
                "• Mass Member Prune Detection\n"
                "• Bot Add Logging & Guild Settings Change Logging\n"
                "• Raid Detection → Auto-Lockdown\n"
                "• Message Spam → Auto-Timeout (10min)\n"
                "• Mass Mention → Auto-Timeout (30min) + delete\n"
                "• New Account Filtering (configurable age)\n"
                "• Invite Link Auto-Delete\n"
                f"• **Every nuker/raider gets DM'd 'Nice try.' 😄**"
            ),
            inline=False,
        )

    elif cat == "fun":
        embed = discord.Embed(title="😄 Fun Commands", color=discord.Color.gold())
        for cmd, desc in [
            ("ratio [@user]",               "Ratio someone into oblivion"),
            ("iq [@user]",                  "Calculate someone's IQ"),
            ("roast [@user]",               "Roast someone (10s cooldown)"),
            ("sus [@user]",                 "Check sus level"),
            ("touchgrass [@user]",          "Tell someone to go outside"),
            ("skill [@user]",               "Rate someone's skill"),
            ("ship @user1 [@user2]",        "Ship compatibility check"),
            ("hack [@user]",                "Totally real hacking 🕵️"),
            ("brainsize [@user]",           "Brain size meter 🧠 (alias: pp)"),
            ("coinflip",                    "Heads or tails?"),
            ("dice [sides]",                "Roll a die (default d6)"),
            ("rate <thing>",                "Rate anything out of 10"),
            ("rps rock/paper/scissors",     "Rock Paper Scissors"),
            ("8ball <question>",            "Consult the Magic 8-Ball"),
        ]:
            embed.add_field(name=f"`{PREFIX}{cmd}`", value=desc, inline=False)

    elif cat == "info":
        embed = discord.Embed(title="ℹ️ Info Commands", color=discord.Color.blurple())
        for cmd, desc in [
            ("ping",                        "Bot latency"),
            ("serverinfo",                  "Server statistics"),
            ("userinfo [@user]",            "User info (alias: whois)"),
            ("avatar [@user]",              "Get avatar URL (alias: av)"),
            ("help [category]",             "This menu"),
        ]:
            embed.add_field(name=f"`{PREFIX}{cmd}`", value=desc, inline=False)

    else:
        return await ctx.send(f"❌ Unknown category. Use `{PREFIX}help` to see all categories.")

    embed.set_footer(text=f"{BOT_NAME} v{BOT_VERSION}")
    await ctx.send(embed=embed)


# ═══════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════

if __name__ == "__main__":
    TOKEN = os.getenv("DISCORD_TOKEN", "")
    if not TOKEN:
        print("=" * 52)
        print("  ERROR: DISCORD_TOKEN environment variable not set!")
        print("  Run:  export DISCORD_TOKEN=your_token_here")
        print("  Then: python digit_bot.py")
        print("=" * 52)
    else:
        print(f"Starting {BOT_NAME}...")
        bot.run(TOKEN)