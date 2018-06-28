# This file is part of SecureSkat.
#
# Copyright (C) 2017, 2018  Heiko Stamer <HeikoStamer@gmx.net>
#
# SecureSkat is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser general Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# SecureSkat is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with LibTMCG; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

SUBDIRS = po

DIST_SUBDIRS = po

EXTRA_DIST = AUTHORS BUGS COPYING FDL INSTALL NEWS README TODO THANKS ChangeLog

LDADD = @LIBGMP_LIBS@ @LIBGCRYPT_LIBS@ @LIBTMCG_LIBS@ @LTLIBINTL@ @LIBINTL@

bin_PROGRAMS = SecureSkat SecureSkat_random SecureSkat_ai

SecureSkat_SOURCES = securesocketstream.hh pipestream.hh socketstream.hh\
	SecureSkat_misc.cc SecureSkat_pki.cc SecureSkat_rnk.cc\
	SecureSkat_irc.cc SecureSkat_rule.cc SecureSkat_game.cc\
	SecureSkat_misc.hh SecureSkat_pki.hh SecureSkat_rnk.hh\
	SecureSkat_irc.hh SecureSkat_rule.hh SecureSkat_game.hh\
	SecureSkat_vote.hh SecureSkat_vote.cc\
	SecureSkat_skat.hh SecureSkat_skat.cc\
	SecureSkat_defs.hh\
	SecureSkat.cc

SecureSkat_random_SOURCES = SecureSkat_rule.cc SecureSkat_rule.hh\
	SecureSkat_defs.hh\
	SecureSkat_random.cc
SecureSkat_random_LDADD = @LIBTMCG_LIBS@

SecureSkat_ai_SOURCES = SecureSkat_rule.cc SecureSkat_rule.hh\
	SecureSkat_defs.hh\
	SecureSkat_ai.cc
SecureSkat_ai_LDADD = @LIBTMCG_LIBS@

ACLOCAL_AMFLAGS = -I m4

datadir = @datadir@
localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

