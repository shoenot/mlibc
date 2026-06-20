#include "sysdeps_shared.hpp"

namespace mlibc {

int Sysdeps<Tcgetattr>::operator()(int fd, struct termios *attr) {
    (void)fd;
    ensure_handles();
    uintptr_t g_term_ctrl = find_capability(CAP_APP_TERMCTRL);
    if (g_term_ctrl == 0) return ENOTTY;

    TermCommand cmd{};
    cmd.tag = TermCommand::Tag::TermCommand_GetTermios;

    SysError e = ctrl_send(g_term_ctrl, cmd);
    if (e != SysError::Success) return map_error(e);

    Termios t{};
    e = ctrl_recv(g_term_ctrl, &t);
    if (e != SysError::Success) return map_error(e);

    attr->c_iflag  = t.c_iflag;
    attr->c_oflag  = t.c_oflag;
    attr->c_cflag  = t.c_cflag;
    attr->c_lflag  = t.c_lflag;
    attr->c_line   = t.c_line;
    memcpy(attr->c_cc, t.c_cc, sizeof(t.c_cc));
    attr->c_ibaud = t.c_ispeed;
    attr->c_obaud = t.c_ospeed;
    return 0;
}

int Sysdeps<Tcsetattr>::operator()(int fd, int optional_actions, const struct termios *attr) {
    (void)fd; (void)optional_actions;
    ensure_handles();
    uintptr_t g_term_ctrl = find_capability(CAP_APP_TERMCTRL);
    if (g_term_ctrl == 0) return ENOTTY;

    TermCommand cmd{};
    cmd.tag = TermCommand::Tag::TermCommand_SetTermios;
    cmd.set_termios._0.c_iflag  = attr->c_iflag;
    cmd.set_termios._0.c_oflag  = attr->c_oflag;
    cmd.set_termios._0.c_cflag  = attr->c_cflag;
    cmd.set_termios._0.c_lflag  = attr->c_lflag;
    cmd.set_termios._0.c_line   = attr->c_line;
    memcpy(cmd.set_termios._0.c_cc, attr->c_cc, sizeof(cmd.set_termios._0.c_cc));
    cmd.set_termios._0.c_ispeed = attr->c_ibaud;
    cmd.set_termios._0.c_ospeed = attr->c_obaud;

    SysError e = ctrl_send(g_term_ctrl, cmd);
    return map_error(e);
    // no response expected for SetTermios
}

int Sysdeps<Tcgetwinsize>::operator()(int fd, struct winsize *winsz) {
    (void)fd;
    ensure_handles();
    uintptr_t g_term_ctrl = find_capability(CAP_APP_TERMCTRL);
    if (g_term_ctrl == 0) return ENOTTY;

    TermCommand cmd{};
    cmd.tag = TermCommand::Tag::TermCommand_GetWindowSize;

    SysError e = ctrl_send(g_term_ctrl, cmd);
    if (e != SysError::Success) return map_error(e);

    // terminal responds with send_packet::<(u32, u32)> — cols then rows
    struct TerminalWinSize {
        uint16_t rows;
        uint16_t cols;
        uint16_t xpixel;
        uint16_t ypixel;
    } size{};
    
    e = ctrl_recv(g_term_ctrl, &size);
    if (e != SysError::Success)
        return map_error(e);
    
    winsz->ws_row = size.rows;
    winsz->ws_col = size.cols;
    winsz->ws_xpixel = size.xpixel;
    winsz->ws_ypixel = size.ypixel;

    return 0;
}

int Sysdeps<Isatty>::operator()(int fd) {
    ensure_handles();
    uintptr_t g_term_ctrl = find_capability(CAP_APP_TERMCTRL);
    if (g_term_ctrl != 0 && (fd == 0 || fd == 1 || fd == 2))
        return 0; // 0 = Success (Is a TTY)
    return ENOTTY; // Error (Not a TTY)
}

int Sysdeps<Ioctl>::operator()(int fd, unsigned long request, void *arg, int *result) {
    (void)fd;
    ensure_handles();

    if (request == TIOCGWINSZ) {
        struct winsize *winsz = static_cast<struct winsize *>(arg);
        uintptr_t g_term_ctrl = find_capability(CAP_APP_TERMCTRL);
        if (g_term_ctrl == 0) return ENOTTY;

        TermCommand cmd{};
        cmd.tag = TermCommand::Tag::TermCommand_GetWindowSize;

        SysError e = ctrl_send(g_term_ctrl, cmd);
        if (e != SysError::Success) return map_error(e);

        // terminal responds with send_packet::<(u32, u32)> — cols then rows
        struct TerminalWinSize {
            uint16_t rows;
            uint16_t cols;
            uint16_t xpixel;
            uint16_t ypixel;
        } size{};
        
        e = ctrl_recv(g_term_ctrl, &size);
        if (e != SysError::Success)
            return map_error(e);
        
        winsz->ws_row = size.rows;
        winsz->ws_col = size.cols;
        winsz->ws_xpixel = size.xpixel;
        winsz->ws_ypixel = size.ypixel;

        return 0;
    }

    return ENOSYS;
}


} // namespace mlibc
