"""
/*
 * This file is part of the pypicokey distribution (https://github.com/polhenarejos/pypicokey).
 * Copyright (c) 2025 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
"""

from enum import Enum

# "SW:6A86" on its own tells nobody anything. This covers the status words the
# app can actually provoke; anything else still falls back to the raw code.
_SW_TEXT = {
    0x6100: '仍有数据待取 / more data available',
    0x6281: '返回数据可能已损坏 / returned data may be corrupted',
    0x63C0: '校验失败，还剩 0 次重试 / verification failed, 0 retries left',
    0x6700: '长度错误 / wrong length',
    0x6881: '不支持逻辑通道 / logical channel not supported',
    0x6882: '不支持安全报文 / secure messaging not supported',
    0x6982: '安全状态未满足（需先验证 PIN）/ security status not satisfied',
    0x6983: 'PIN 已锁定 / PIN blocked',
    0x6985: '使用条件未满足 / conditions of use not satisfied',
    0x6986: '此命令不被允许 / command not allowed',
    0x6999: '应用选择失败 / applet selection failed',
    0x6A80: '数据域参数不正确 / incorrect parameters in data field',
    0x6A81: '功能不支持 / function not supported',
    0x6A82: '文件或应用未找到 / file or applet not found',
    0x6A83: '记录未找到 / record not found',
    0x6A84: '空间不足 / no more space',
    0x6A85: 'Ne 长度不正确 / wrong Ne',
    0x6A86: 'P1/P2 参数不正确 / incorrect P1 or P2',
    0x6A87: 'Nc 与 P1/P2 不一致 / Nc inconsistent with P1-P2',
    0x6A88: '引用数据未找到 / referenced data not found',
    0x6B00: 'P1/P2 错误 / wrong P1 or P2',
    0x6D00: 'INS 指令不支持 / INS not supported',
    0x6E00: 'CLA 不支持 / CLA not supported',
    0x6F00: '未知错误 / unknown error',
    0x9000: '成功 / success',
}


class APDUResponse(Exception):
    def __init__(self, sw1, sw2):
        self.sw1 = sw1
        self.sw2 = sw2
        self.sw = sw1 << 8 | sw2
        text = _SW_TEXT.get(self.sw)
        super().__init__(f'SW:{sw1:02X}{sw2:02X}' +
                         (f' — {text}' if text else ''))
