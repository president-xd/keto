"""Windows-relevant physical-memory image formats: crash dumps, ELF cores, VMware, hiberfil.sys and their codecs.

Ground truth, never just this repository's writer against its reader:

* codecs: ntdll's RtlCompressBuffer (Windows; skipped elsewhere), ntdll output embedded below (every platform) and
  the published [MS-XCA] section 3 examples;
* containers: keto.testing.synth_winmem, whose field offsets are written from kdmp-parser, QEMU, VirtualBox,
  crash-utility/Volatility and the Vergilius PO_MEMORY_IMAGE listings, independently of the parsers; plus, per
  format, a hand-assembled file or byte excerpt taken straight from a documented source.
"""

import base64
import datetime
import hashlib
import lzma
import os
import random
import shutil
import struct
import tempfile
import time
import unittest

from keto.formats import vmware, windump, xpress
from keto.formats.memimage import detect, open_memory_image
from keto.framework.context import Context
from keto.framework.exceptions import FormatError, InvalidAddressException, UnsupportedError
from keto.testing import synth_winmem as sw

PAGE = 4096
NT = sw.ntdll_available()
HERE = os.path.dirname(os.path.abspath(__file__))
TMP = None


def setUpModule():
    global TMP
    TMP = tempfile.mkdtemp(prefix="keto-winfmt-")


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def tmp(name):
    return os.path.join(TMP, name)


def pages_of(pfns, salt=b""):
    return {p: sw.page_content(p, salt) for p in pfns}


def filetime_iso(ft):
    t = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z" if t.microsecond else t.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


class OpenMixin:
    """Open an image through the public interface and check every page against the truth."""

    def open(self, path, name="physical"):
        layer, meta = open_memory_image(name, path)
        self.addCleanup(layer.close)
        return layer, meta

    def check_pages(self, layer, truth):
        for pfn, data in truth.items():
            self.assertEqual(layer.read(pfn * PAGE, PAGE), data, "PFN 0x%x" % pfn)
        present = set(truth)
        got = set()
        for start, length in layer.ranges():
            got.update(range(start // PAGE, (start + length) // PAGE))
        self.assertEqual(got, present)

    def assertAbsent(self, layer, addr, length=1):
        with self.assertRaises(InvalidAddressException):
            layer.read(addr, length)


# -- codecs -----------------------------------------------------------------------------------------------------------
#: ntdll RtlCompressBuffer output (Windows 11 build 26300) of NTDLL_PLAINTEXT() for (format, engine) = (2, 0) LZNT1,
#: (3, 0) and (3, 0x100) Xpress, (4, 0) and (4, 0x100) Xpress Huffman; lzma + base85, records <u32 len, u8 format,
#: u8 engine >> 8, data>. Regenerate with ntdll if NTDLL_PLAINTEXT changes.
NTDLL_VECTORS = (
    "{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;8OS=0bKxIhCCNR@B{a3$>QeKOlp-8#sgWUNJ|x$*yh+6*O3~qoMq&CKR<=6(aO`$K5bF(ww5oR?f}#^z)=p4X"
    "l5Ort=#$(y}&6f=Y^C+a+sbr2Ms_xg#v2cnE!>%m2+<XkubXiKce&4Qi^}ecR4-MUQ*)IsQuA3CIU7!-80hKVuX1nSBD%z?Y!m}Q7FBXv({oc7FlxL0^"
    "|FauiQ=SCg5cr8F6TjnsrqCQcr(qdVp~DzZt91SxLpvBFICrL)!U+GQk&Ck<+GcN;-X-Pk_GX{M%NWeC%#XUIx@arIkpK?EQ5Qj%{BwIaaecGzFRLgQ;"
    "jQS@{}!46m#A9#@;jzrmF1&n%UYZ?vsOW0iaHTkOy35j>b(Xy)~YL$L>Ll_=^zKIwO%ou6L<mVomO18>oY;nx|2FrT1&3*|D5;hpepFNey@D5F_OmY$?"
    "nTb0D}rCnH)a|b$ore<si;hH(5Km#z9S?K##^aE{}z=zaEgW%>2tW>wFNnzn;Jn>6R@LaIN+mP=fHUBT^YS4dUZx7nT&%XA!=+I)+chSOJ4R@{p3x8EI"
    "3kj86`1xz1K`e2!*HiWb-Q3ndx)#HeDI^M(X&jCtko451#;A82@y);TxDB>)H`EgX0Zq?3>KD5jS>!EHj<3S;F`huzAG!O$EsZ~k_FS-0J!=Hk2~6Ldl"
    "Kk;${!hyW#vT5Ylq{St9&*#ew6g+d?iYwgV;~D}qu!U&_o&AEw_+^Srj*-4p9~q3Eg;V&z=J7I$BGXzot~_b3~u#<9BdQmGo5Gf&_K14_FlCeuw}K>Wf"
    "t-XglOOy!4jQvWtn;-SQ@kX9`_Q(nAkO4YV77}CfcgSmhY&UqI2*0-`L?fnC$<gAAUKK+%6MwZsL?#FbR!Z7hJe8RRf!%w2uMw0Lx(@Yov3dSNi!TELe"
    "p6mmpx&E(1n&;oc}JOs=h#xL#Q6y((^3$aMB~O2qL*rKBvPMq9YFpOBxJw?qRBtu{9*N7V_EzT9ZxiXjeTTZ$mA;&o$e9CE3tw%X>XA57;f)8OIy_W>)"
    "(9;fFK2wGHc)kMGVsl4lA*GavzMvUNq%%%LYr*Jb07NdlQo@kylq4(&)1#W=0L?4!Oju43LykY~xa4%1kt}{P~e~jGeSO8FBU{TO;BnI?_`o@TrX95m*"
    "Xiz4?(UmWtae~EEb}GQ08H(fhYXCiu<`bBtK%;tUBQ<xt=h389%zQ3eO&A^RT9-KE=%)_!D;}Um^s`DQC=})Tmr`oYS5n+&aZ#XSicjp@*RcLwu=NKTR"
    "SUbN=)wPSG2%*Pqmum&6$9(w5aUD4-IoI2hyM6zK;UF<DK;b(QhH&?m8tL@Cq!sM0zZ=18NmoY5NyU6mk6l+JAk(@nL!qNx+op3;9)_iYKy&!Z|nVe`B"
    "hV4cA+WaAc;F!0xw*SYnUa$onYni17Z}BZ!1roz&ocAw^S%4cTTqv;3WAi^|Obj?RIgwnzw%e1)j>|xEK(Kt$k^dujl_|bd<LJ!6=j4dz<+B&yY8p_Fa"
    "53SYf0eJ-CqZdNR+-z`Yqvb8H|u{Vq=P<@9iSys|Ta4@cpLLCJEQxW*7R;O1sx{w=~Iy;Ck;@VtQP(j7NBKYdE;v6LKHSIX6DOzsM)f{!}*?(`Q$>4t%"
    "(Sg>nUjxE2;ZzUNIT<gqrhJ(lERnifovA_WpzH85D<=?vC^Pc$ZFpMiga;W^|L63U<jvl4-0w&>D1ENGlAe=XN%xW_Y@!b+{yPO2t@o^)<FO@C^cQV!@"
    "7R3QDmWaR@z6aR0P<ZSbB`{Bv8CQyyFxcM0&hs?8?bX*txY+}+&}KIIpP4uQ9tdlKj~_rtUS>L-D8jXn1wEM&Pm?`KJEIAwq-~{rI{~0I^9lUuzd|@!E"
    "=?W@75KdKaJB!;e7{tLy@&g~7}Y2=m^$-jb8#f{r8~5`ej9cRV(<yoKrxZg1jD;=SgAGMAe<4ZG}bpDP%*>pn=Q@bk=8^L1Cj}y_yugMzN@N%#&MX=x~"
    "Iv6aQgH-*)G=#c!!!AnG!{FaU)(M4M7K|4A13FgI%3+8y<x9#2zYjj-ojYpxqq9H{(*{I7|fGb=x9D4{1BorRtY}d^!o2G7DI`(j+seIeBtHWKV2*oeG"
    "0A<Et%z_cy$X01~3jBIdVIUv5tSX>f78x^Y9ZJh7zr>K=IjEk&iO5LbZVh+<CiLpl?zH?|A{&&<}eRb39o4o?4msaf&OwV)kp-Z*dzB=5JCuzS^=<L(1"
    "SkvrnR&PDe1O5lv4yj9%`Qx)IGn20N7X6mS$kDF<_bv#L~&VytRr{n_Xtl@;UbavF7yEl6z$4wYhKT_=Z_MAw~Z&e(X`7ej!mEA$uZfzOQh)Dd^Pl4aC"
    "UB?4|zl4l9?pbkMIO}F(Y%?;jw%WRs^VD|n@as*p{yrFuI7r+w+IwT5N$n*3k*Tdwfu~9Tu+OLG>e~%qq0p=;!mg;$+hgnF(v?mgYSZ$ot}qaWN5m}sY"
    "bK`_2gqk=OiZ*WI+Ti^G+#k`Z2pD*;WibBDoihZzyn!O&ayP`UG6)DZ<$XuUo8^1E}Q%y{A~$U!bm}_*z{D9@Ds201H-5J(P00IzC7~PTpZOv_idi`o_"
    "v{jJslh@;bY2$#a3dfR)g5iY2gL3Fs*T5t%zp}^ky*=9PnB)j8C`d!My~_>7TPotMi+jSB#&0RFR?5xKV5-x2hJoY`t2R;eF@HqmzTUeTdPoAj|q_z{9"
    "V<pv#?V1nR5XANP}!95Gp|zoo_f!)ItYh;icfpc0py4KUfAuz2I|S%Y3vLPhwhw+)O(ISKzq^SmU9Aqy>~lGlN?m^02Oz6rXeA23jCKt0w~!w2{sVgK7"
    "Yy&h*&A3EJ_I}UeW?)@DXpDsCr1|-PP+t0}1eFQHIe7F!IZZoZEqLF{L(T&?sl!vLPUVyUE3B}@{Y1LDJvi#ehlusZOh=qFPzRzHh5Gv&^%_DFiUWzGW"
    "25ISVC{d^p$ye%uS2QJzWBvhCM-*m>Dqe4&L(0s}<vHTDjo(Nu2!vVU<;nsQ?z{Z@p2q*kL{<RY*bp`3G96GNP=&DI&1>I>;-DFj0rC$k`3Z^OY5^<Yn"
    "%0wCs3$2&vCw*dNhC$ur!TH$vXSKEsTOhai_7Rtwu=@zKRZIDK90oIskx{ej4WIemZNI06PbRhh79fpFFlhsQ-x+#88!F&^i1aO9`fXOUpmy?%dOd_vW"
    "t=#(dBkSn+<qA+NFAHqE%1$96q@EhRH5mpAkcIml09Nsgy`az`A-Gmm)tnk)BHzJSAy7zzFlg@4&)pwqcW5vkOh809SkxdjG;s2=IFfcVD<+Mz#78s$I"
    "<OH|TAz2rgxzDmPuCnkM5WWRf1gPc+8eAY4mTpwU#d5CZykK+W#Rjg(UFHWqobO1U2wO|gw$lZj{?;<nN{@V^@XEz06<w*$zWRErY_F}=mp_TON7rj5Z"
    "L3NY4Zr5mK{B4#oxU$z8qsNm_CL|<~KCB3tBhrb)L0lpv7d6Op%TGBWw%NdqfRaUZ3aonbjMx<2=4)MKkUM|YVze@KKqe*_}K}NW%33g{4M(Du=AiO*m"
    "u9&#9gv}%QnD^?m*gIP_9;AU*rv@jRQwFP}>=K##Lxko>cdNRe%ll>8o0j41DqCgODL-nWxPZ|ZN01$s&}Egr@nU@S;p$~Jv1ZVYx{j7!uW_)K#DPC-f"
    "U*lyzOw$~AqHT#3ZV-h8GGAFPCf`E=D*rPxN@IQUPL2Xw?Z%#`03rQze|NetMs{yT_%E{C7u&;#~6VhL>9H-<0a;-EMjV!L{nji4DoJqlX5hCb5C1i0l"
    "@Cs5gO*P%mu?da@UK0r_A@O{pS1la<CjTaKLOaLGc36i<px=Rp4}5OWoB`H@EY>&5ZH?AEtrM)(2A#l2yVu^h&bk650nG+<`E+I^gLIIFdgi?lX8xXIU"
    "a&24Ls2omQ`shO9Kp`PEZ1p9^t1K~A2Cw%Ezk&Sn?_-ZpbE1Ws32t7hfs#r*Jf>>~Z_`D1kd&jmX!Wh#>|ZUbmdSoCmp5Rg300^WL%+OtNnWlNRt6cRX"
    "G$NQ`3eWdN8x#TrNV*3AuHwFOx3@t5<dfNn>5eQjk^+vF+i|&(<7z8C*_yNk6^7!=G{OC)hmL^AUCmH_VF=aJY*pQyp(JJ0y-X<R(Ye%dx+whARvlH3$"
    "P?C$l`oN9V>^`t5)n7N!II0|K^TFH^la%ceJj?3u^K|fFjMTz-<jl?fv>q<{UibaV#ce^ln#tMvhFCp{Zi0f*u*kmsD&r#|W7w5PcH<<yYB%RV&%U)-%"
    "E!UvRFZOPhA&l+FG=+hZRiLfA|%NA)7~Obb@6BkLH6jQYf_9{2NDvoP6fKEABPG`f4{r!{KIzf_p+F3GuOX52%8APXf-~#ff+E%J2#W|Kx8(1Bby${)L"
    "ZYB22=bSMk~&@Y*)%bdU~!UL10&jx#;>LNONsMhP?wj9smt<Pr^aNVIANgn+jW*mCBHLJ6`{q-ZVH%JL6?pbY;+Q;@EE+_Ov<g6IN$X-ni~p<~1W?pXt"
    "<fcC>6d5>88;TddE%yW_kxWo^#Xw9J3|BXss`4loo!s{TGPRl4?m*WJ|hLJ9$0GR6r_Zn$=IoLo1*9hAOYu}IxLf**#|L1*CoJMdk<0{_DIvSan6VeTu"
    "Q`5W6|rqUh&-$LR>YOu+&?Bknr<gPvfR7}~@Fa=aYG}?OPVU?WGpkWXT<Fy6FGFUHGGc7F5bT?83vn^hKACq5sk-!lP5OP?h@50AvP#uwUt7ow`Vi3?%"
    "K=tZK9l?EH=AT=Ke%M=Y52aH5wSeHSO5BqcxZ-t%Mx2RNyMjN7*+JAV^Q;L-#5>p-olbtUlMLT7oa)fKfbTy6^T@SnUdy~<|Ln1V3+@~CN`9=puM1yw2"
    "$AFOu&A$2gAf+iE9QG!hvHk7q7=Yd(4<*q&z+hJk5!a#F99^Y!tM{k@<R?@x6)i7LQJ5J5$m|j^i6?UnD74#zOn*Xg3Z`HvYpNp<l@Q+lvrtdoi-21sU"
    "^+FZyJ4RL?Px>N4D+4M(TW<g$iM0ZF@f3P#H-AerGC}Cu6k6`UjBON3Cv)C$dfg**a+lrt>V{ToG^v3{3#H*Im)Gq4|3mNFQd}6~*p_y4<ZhJ`<5!kz-"
    "-z{7k6y`vbX#qy5pD@)P{#?Vq9L3#HVjv(&6rV7DB!F8KGIvr0txtx{7|&z|>bescy2Wp++*O!r}`NbavGTbPH;F(srh5JV6i^E1j4xDbDOURB$tWTd("
    "bA+5(M3@N&bocNN;3|4p=T`)t04!F^E!@m2oYDQpTbmyV?q1Wx4?Kdy*N+7(jMc$rlH#Hn~JeHQ_QhXnrA(%)S9~Y`YJi>*Kpix#O<5KiPEjL<86XHQ5"
    ";nbEX9u(0Sc<tSR_VCwh!b#5Cp^;@1-$2V!J2zt#NSDldpTh9Ym3gee`*`LKx$|cPj6ZiL^8tA4@;8Zzq5tXq5mOpp{-7TfdR3O~V+Mh8mTKFA_?z(0B"
    "Al>~Hv6#pH4Cv{xor7s`mJEdtaR4^!Vvvn)&yp{-*rE`mG136xm&cNz^q|OMfkg~bL8m6Bk~0N_4T-Aw?0oj4{SZoACBG=@xTIk|HHUz-mo78-`t)Tn3"
    "@{V_O65!_vHQbkA{0gZ$O1ZoIH|&J%SgShA-%GCEVdE0>1g*KvB-kQH-9~dzTQCetbgXXiM)ZrCVfuHt+$g$7gGAJSVLN%`dO>>AG44xO!ZYJxQ8h=;`"
    "iWVhE|@L}Q;p=#Ru3y8HziE+$Ike|~VdcH-~e1moVtmWH$z$a44e2+!yB1487umNm#&zG<);7;yn8e0xG<dYtN1E43n0kn|p&7A=$2{Bw3~^=vA>P;lS"
    "tbqZF|L%dmnqqKwnM!L1Z&OpGEAf;Dv#R+ThydB72&wVniv3!f#u==jQI<sIntYVZ*&N9KD%aRRS+G2+-+Rn%fceR<eTs1&55-E^C+oGQjnf#FT)d%95"
    "M)<n0^j(N3x^&g)@JDL=hMs<P1#Dr<k@f~e?BQy}L0H};VZDQXR<!Z5-mBMCIvwh;)H6|A^~N5w_{1Q_s)Ysv+{jpP?#kDG)pAJE^2x(2;TZDIec*YgC"
    "(C<>;<gG24&#LNoe@VW&^P(CA6Qz9JuoHe=C?R^C9%T)DLg6vD{nDOCKSFU;;Dgi`C>h$4TdNXDFvNzdKLS@mwE|LQi@$dZAkJZWSXnvAwZ&aZD-MTQ+"
    "?j1awp_W#!t^{=PSrMwhd$Fiey@T9+rM^K<_3E2O|X{8Mj$p2;mXG>E*nv!m}5cfFU*dDM)6Wp{%PysViFEStjoMwM0oGgjbd9JRm$@z;+7UVzaobT7v"
    "c6syf>EBBxzvD?t*FTJ&yHO=iFIrnL8ip{s7W^!8*lry*r@iw3JyH40)#f}d`#;@Qi2CF3Yx0Y84^C=5}DH8EGhn|vk$ctctKbI*0eUXZo?qE1i_aHy_"
    "L1S}p@*8~AVLHw9CL>%pFk~Ff%1{;tRg?OFG`H0ni)r3O)EF{yR|KFFX91>usYI8M=@UwIF^LF~N8`p*MKR-NH>0YUDBW*s|S(DGJ&`=5DO93y|jbs1n"
    "po!SDDG<x#2*y#2M*HW4^a{b6oI-|2C#s!c>7?JNSKvn0NpM$;mi8!b>S0y|r20uLZ1kwMzl8=U?IaQlV@d%`c3Cof6+6DBcKcuvoSpn*yn@G3<5Fwyh"
    "{fTHbnY<LQB#U5jSYVagrs{xkDi=hS_7cXD@yPjJjagVaxw61Aj*2Su>a2^$NdDJQi;@qTqXF9!l<MFz%+)&veoko+@z2n{==n2m0%nH5}RJ2sO&~Jv6"
    "NcR{>%VA!U*^_aQ}XVxkq%&D8e8O%0_3TM}Xo0#+s2klWkt4-SPXG1uS@891+kUyWH8k8OIZUqeFGEy#V1lp877;QJyPTYgD*($yfYYJj?}AMEMW+SSI"
    "aXLP_t=`11>7de=lKj7kV1NC%G+ojR4d*_~)p55+ufy5Vi=Q_4^zZh`vaeL2mzpl4Rfvg6}Q9RKu#T^HzLLs-bmYJvGFTIb22AO_CLwo2nLaL5vPm)+s"
    "G-|lrO`NS)Oi`oa>&fILSH9ApcJ8(<{*En}EUfSPMmviJoTI~>AT_rTe>o+$G5g?kdZGY{LQ{WGmh0FDrO@r8RSJtQ*ht~oZW8ty26@;nvpnRPR43tA9"
    "m+<g_4Ba*!0DTM(M(kH=92y%S;j3(k{nuASAL5;Qr?RF-nhjvQ67RH?=88U@&Nzp(Dk`QX_?9HhJ^YTEg?^9~{|$15){d(92;VMuEn`Lc1jIm7Q&Ku~0"
    "~4f4bN#K2m{6(*1UDi`g;fX+#jG)pCc~M)F0JUHS;M$Xs6l71v0tFUOH)x@y_1GPn$Ul%wEX#|M|9)%AyQ@I(*o(|L9f`%$Twi0ho>L(nio?ca~wZ4=("
    ")U5T`pn+5e~P^!<?|d(4x9!^S|V0?MJi8xC}JurT39!kVCcw`7B~Hy4!kp*LoE`*KG37(NfN5u0+{Nkv~J})zRBB^ZizUg<Xv_=c%+*k<yFZd#^Y6?_2"
    "G@Dq7|FrF+V%PAlI+<bdo-t~{qj@!Y!jN3N?2)2b5kLrU@;fYmvR(7Ffo+@cAep(vT(7prK1bAo#$vPk~*5nguFx+--XV7mOHv)Y`j55-mk1SpYxeK@("
    "T7UP+%B>y7@bbhg`f72aGIHw>}WgJN_)KJI53_M`j#RZUUEI^r4S-Wq^uqd<edA-@v>A&RJKaq(Kw#fjOGJSNy^J%4L@xLEmMLf1U8@&NWg<l7+-F$>E"
    "QBF}fDQ-y^>JP<u`ElLF0%C4#lKp#cY`hQ7&ii798HTt;SCpX)D|`?Qy1thyuoJ$xZ+m|<lHupko~>(=H1_}u4?RrckxD5&NbhI?TBiXECk(Q1gsxLj!"
    "*StA4#iqg3O@6TwoeOnyREYzTV3AiLDehzGWxw^w4!cjB2|bi+b7`O&0PETJIk1E&2S@C9JqUU1-Nt^1b5?8lWV89Nv;Gf$~$gQJM@K=;8R%&+|%SCtt"
    "N;TAx4>Hn+0Sd&Q)3@bJ}|)@IHal>&y6fAS2hRLN?dEJb^mx09SE6&0yW#LhoG0x}(~#?*1o+RW=HPFypArX@CYs^g2HqOvD_19L`}<ZTtvO-Gi_Ka^^"
    "6_P762AhFD`@)RrqgFB8*MfVNz^MQX6ZxdicoY0tLDo?Nb!GTQa;5ma^!a--MS%K_2AEpBTr^6N%N3i~lO*lTv!7&KASHDH&m-I~xUpsreHElnoklytE"
    "LOX~~R%lir`b3>RP4Es0oP}=_7kNd}{1(H7alxjGE(o7VgkIve2|EDN;q2QmCH{(dW<W!5qAO}bES>*qrAk_kcBXPILvfju8u`~_P%s&FwuSUgl(33c8"
    "4Y&ZkjhR=o4Jm1$B+O@ZLY=c)4(~Qt8P*_$00)L9oNihWD5~6QnwOTu>EOO<qh&DMzhOT75!QoAI6b*tm>6^}FJbiXDH=?{i{7dZ{<$$_Q~_&Xf1v6#j"
    "X*3xWG>F(VyJnCLK+DojUDs4HwKrHX^*)I^$@2-O{=>+@qKe#&rk1Fe)fxAugxFlZQ=#jSK>i;$FKXGLG)5uEIP3F13|wN)&wf)TD-dvvHzl1q)gr3MH"
    "RCIv{ZphabIPdUPU{=k<Ti{sDdpvT05V91}r0AyI0i6kmDxsOv|$5`znIM>TGQkXMlzRPzQ20f_|>Qpd;~yfhx^s{EP&INcACTdoXogVj&k~8VBhhi%$"
    "&qut!Pvj@m=l{MWG+B99DeF5=tFdw%Foy&g?6Oke_kp4z#|!)r#fRRq>K^wGjtZp|MaWF!Ai=k9yFT*u2!1i<bECOV{=m@|b|FYeS3dA)Uy#_1Y)$jfS"
    "b<{Jdv1X(8_V^VIdDFZG|Tp4**QR~g3whq4;pAiwDqR5HR)7WQ;6LZbc<8>O2^|%Mc7qv+;Nk0qM-15%$FzLYAY?A<hnGa)>M|5sEY1ZvRZ1`@2+mL@7"
    "urt%X4r_fJ<Z{UO=dI)pBBq0KopUj=KnkH|iW6lg*BknD{FSC4O+Fb<_)yCys-#1z!wbBqT5r+{%JJ?5!(`>ldK-G0{GRXK`mGI@|IZl?P!R;Pt{l;;|"
    "EYxC`{v$X9h>HZ#zcrv--Eg1cX};P6_%cMGXBUegj3$?OYT*Lb-q`bT!_~fH!u1xAcw<=McbR;gZI8+`%N1sy)4Ul@bD(BUFn5{1!F?I&UbM7FW|8kpS"
    "^x}VCk}eE_5`XAu-nEg?nYk9!d4G(oQgAWGnn2ONl0+0`IG2e^Xr=wQI;oOfl)jsIwr&VD%_#w)3fB*NsD)^_mq(6JICwL~zK#O=|I~y*mggkdxmWjYh"
    "Wf8j5)9ds)-D3_w6>VdL;ib5{RdYI*BbciW)wT0>!LgWyGUlfSJdt<CEMzD@y_k@B?}cdxn6l&0?OdIE>qK@8^}M4FPt<(;lgr9-SEa|foU2UauG+#RC"
    ";DQODD>2ZUo#Sl!R@qnS?3Uk;UIr>W;g@UDOSGBUe+}&AhB~sj(I<#$9-uVX7vk|aw+~A=q@Sna8<zPP$*}HRt5%RCxCTo&@<XBYqdOWx6oTjR`Wp*%Z"
    "8*qqT+VMTks$M}l*M7{~+zi?6!Y;Zw=p7w-i$u6B(j{wJZ4{-i+YC{yHoAX41Ie$!QSUeDh&mxid#IIzmCD%R1PQe>HCO^Gjh>F~`H&pTD*)~oQR<o-w"
    "mK3k$@axQ3a(EnJyJwf+Ykce_L2)sHFEXC7E^Yhq)CTg4B=M+FA=UJzK7b|{c!;ec|qYDALVt$Al;@@hgBDz$+OWkZFm$B8?^ECt~sr@I(#1|3)boEh^"
    "~Cw@{2OD@SsZn>W@Yse*5S+^+Y<p3WoeDu%4Nv&0$uObaH;LH!1}OfZiBLxW&34s)yW>7kLG&MiEq;#cBZM%R`RYsh>PM_zcVHRA1>oTFKqB?zu!UfMZ"
    "%(gtDeR)IKSA00000?#BM`VCtQ900Esm`K18>AalAqvBYQl0ssI200dcD"
)
NTDLL_PLAINTEXT_SHA256 = "0ffce1806e49d8a00e324e6fa7fcd56ca36e0816a59f7700b984700a13ad86a2"


def NTDLL_PLAINTEXT():
    lines = b"".join(b"keto ground truth line %05d: the quick brown fox jumps over the lazy dog\n" % i
                     for i in range(900))
    return lines[:40000] + sw.noise(700, 99) + b"\x00" * 25000 + lines[:4000] + b"Z" * 300


def _huffman_table(nonzero):
    t = bytearray(256)
    for off, value in nonzero.items():
        t[off] = value
    return bytes(t)


DECODERS = {2: lambda c, n: xpress.lznt1_decompress(c, n), 3: lambda c, n: xpress.lz77_decompress(c, n),
            4: lambda c, n: xpress.huffman_decompress(c, n)}


def codec_samples():
    rng = random.Random(1234)
    rand = lambda n: bytes(rng.getrandbits(8) for _ in range(n))
    text = b"".join(b"%05d the quick brown fox jumps over the lazy dog; " % i for i in range(3000))
    out = {"zeros_64k": b"\x00" * 65536, "random_64k": rand(65536), "text": text, "repetitive": b"abc" * 70000,
           "one_byte": b"x", "pages": b"".join(sw.page_content(p) for p in range(20)),
           "zeros_200k": b"\x00" * 200003, "random_128k_all_literal": rand(131072)}
    for n in (2, 3, 4, 15, 16, 17, 255, 256, 4095, 4096, 4097, 65535, 65536, 65537, 131072, 131073):
        out["mixed_%d" % n] = (text[:n // 3] + rand(n // 3) + b"\x07" * n)[:n]
    out["long_runs"] = b"A" * 70000 + rand(100) + b"B" * 300000 + b"C" * 17
    return out


class XpressCodecTests(unittest.TestCase):
    def test_msxca_plain_lz77_examples(self):
        # [MS-XCA] 3.1: "abcdefghijklmnopqrstuvwxyz" and 300 x "abc" ("abc" + match distance 3, length 297)
        self.assertEqual(xpress.lz77_decompress(bytes.fromhex("3f000000") + b"abcdefghijklmnopqrstuvwxyz"),
                         b"abcdefghijklmnopqrstuvwxyz")
        enc = bytes.fromhex("ffffff1f6162631700" "0fff2601")
        self.assertEqual(xpress.lz77_decompress(enc), b"abc" * 100)
        self.assertEqual(xpress.lz77_decompress(enc, 300), b"abc" * 100)

    def test_msxca_huffman_examples(self):
        # [MS-XCA] 3.2: the 256-byte code-length tables (non-zero bytes listed) and the encoded bit streams
        t1 = _huffman_table({48: 0x50, 49: 0x55, 50: 0x55, 51: 0x55, 52: 0x55, 53: 0x55, 54: 0x55, 55: 0x55, 56: 0x55,
                             57: 0x55, 58: 0x55, 59: 0x45, 60: 0x44, 61: 0x04, 128: 0x04})
        self.assertEqual(xpress.huffman_decompress(t1 + bytes.fromhex("d8523ed794115be9195ff9d67cdf8d0400000000"),
                                                   26), b"abcdefghijklmnopqrstuvwxyz")
        t2 = _huffman_table({48: 0x30, 49: 0x23, 128: 0x02, 143: 0x20})
        self.assertEqual(xpress.huffman_decompress(t2 + bytes.fromhex("a8dc0000ff2601"), 300), b"abc" * 100)

    def test_msxca_lznt1_example(self):
        # [MS-XCA] 3.3: 59 bytes -> the 142-byte ANSI string including its terminal NUL; chunk header 0xB038
        enc = bytes.fromhex("38b08846232000204720410010a24701a045204400084501507900c045200524138805b4024a44ef0358"
                            "028c091601484500be009e000401189000")
        expect = (b"F# F# G A A G F# E D D E F# F# E E F# F# G A A G F# E D D E F# E D D E E F# D E F# G F# D E "
                  b"F# G F# E D E A F# F# G A A G F# E D D E F# E D D\x00")
        self.assertEqual((len(enc), len(expect)), (59, 142))
        self.assertEqual(xpress.lznt1_decompress(enc), expect)

    def test_embedded_ntdll_vectors(self):
        blob = lzma.decompress(base64.b85decode("".join(NTDLL_VECTORS)))
        plain = NTDLL_PLAINTEXT()
        self.assertEqual(hashlib.sha256(plain).hexdigest(), NTDLL_PLAINTEXT_SHA256)
        pos, seen = 0, []
        while pos < len(blob):
            n, fmt, eng = struct.unpack_from("<IBB", blob, pos)
            comp = blob[pos + 6:pos + 6 + n]
            pos += 6 + n
            self.assertEqual(DECODERS[fmt](comp, len(plain)), plain, "format %d engine %d" % (fmt, eng))
            seen.append((fmt, eng))
        self.assertEqual(sorted(seen), [(2, 0), (3, 0), (3, 1), (4, 0), (4, 1)])

    @unittest.skipUnless(NT, "needs Windows ntdll (RtlCompressBuffer)")
    def test_ntdll_ground_truth(self):
        """Every sample, every format, both engines: ntdll compresses, the pure-Python decoder must reproduce the
        input byte for byte (ntdll's own decompressor is checked too, so a bad sample cannot pass silently)."""
        checked = 0
        for name, data in codec_samples().items():
            for fmt in (2, 3, 4):
                for engine in (sw.COMPRESSION_ENGINE_STANDARD, sw.COMPRESSION_ENGINE_MAXIMUM):
                    comp = sw.ntdll_compress(fmt, data, engine)
                    if comp is None:  # ntdll declines plain Xpress for inputs of 1..4 bytes (BUFFER_TOO_SMALL)
                        self.assertEqual((fmt, len(data) <= 4), (3, True), name)
                        continue
                    self.assertEqual(sw.ntdll_decompress(fmt, comp, len(data)), data)
                    self.assertEqual(DECODERS[fmt](comp, len(data)), data, "%s fmt %d engine 0x%x" % (name, fmt,
                                                                                                     engine))
                    checked += 1
        self.assertGreater(checked, 140)

    @unittest.skipUnless(NT, "needs Windows ntdll (RtlCompressBuffer)")
    def test_ntdll_huffman_edge_cases(self):
        rng = random.Random(77)
        cases = {
            "all_literal_one_block": bytes(rng.getrandbits(8) for _ in range(65536)),   # exactly 64 KiB, 1 table
            "all_literal_two_blocks": bytes(rng.getrandbits(8) for _ in range(131072)),
            "max_length_match": b"\x00" * (3 * 65536 + 5),                            # match lengths past 65535
            "block_boundary_match": bytes(rng.getrandbits(8) for _ in range(65530)) + b"Q" * 40,
            "two_symbols": b"ab" * 40000,
        }
        for name, data in cases.items():
            comp = sw.ntdll_compress(4, data, sw.COMPRESSION_ENGINE_MAXIMUM)
            self.assertEqual(xpress.huffman_decompress(comp, len(data)), data, name)

    def test_independent_encoders_decode(self):
        """The builder's own encoders (used for hiber files on every platform) against the decoders, and on
        Windows against ntdll's decompressor."""
        for name, data in codec_samples().items():
            for enc, fmt, dec in ((sw.xpress_compress, 3, xpress.lz77_decompress),
                                  (sw.huffman_flat_compress, 4, xpress.huffman_decompress)):
                comp = enc(data)
                self.assertEqual(dec(comp, len(data)), data, "%s %s" % (name, enc.__name__))
                if NT:
                    self.assertEqual(sw.ntdll_decompress(fmt, comp, len(data)), data, name)

    def test_lznt1_short_chunk_is_zero_filled(self):
        # verified against RtlDecompressBufferEx: a stored 10-byte chunk followed by another chunk stands for 4096
        stored = lambda d: struct.pack("<H", 0x3000 | (len(d) - 1)) + d
        out = xpress.lznt1_decompress(stored(b"A" * 10) + stored(b"B" * 5))
        self.assertEqual(out, b"A" * 10 + b"\x00" * 4086 + b"B" * 5)
        if NT:
            self.assertEqual(sw.ntdll_decompress(2, stored(b"A" * 10) + stored(b"B" * 5), 9000), out)

    def test_invalid_input_raises(self):
        comp = sw.xpress_compress(b"hello hello hello hello" * 50)
        with self.assertRaises(xpress.XpressError):
            xpress.lz77_decompress(comp[:-3], 1150)
        with self.assertRaises(xpress.XpressError):            # match offset before the start of the output
            xpress.lz77_decompress(bytes.fromhex("7fffffff") + b"\x10\x00", 3)
        h = sw.huffman_flat_compress(b"xyz" * 100)
        with self.assertRaises(xpress.XpressError):
            xpress.huffman_decompress(h[:200], 300)
        with self.assertRaises(xpress.XpressError):            # incomplete prefix code (one symbol of length 1)
            xpress.huffman_decompress(_huffman_table({0: 1}) + b"\x00" * 8, 10)
        with self.assertRaises(xpress.XpressError):
            xpress.lznt1_decompress(b"\x05\xb0\x00")           # chunk longer than the input


# -- crash dumps ------------------------------------------------------------------------------------------------------
class WinDumpTests(OpenMixin, unittest.TestCase):
    def test_full_dump_runs(self):
        pages = pages_of([0, 1, 0x100, 0x101, 0x102, 0x1000])
        runs = [(0, 2), (0x50, 0), (0x100, 3), (0x1000, 1)]      # includes a run with zero pages
        path = tmp("full.dmp")
        truth = sw.write_crash_dump(path, pages, 1, runs=runs)
        self.assertEqual(detect(path), "windump")
        layer, meta = self.open(path)
        self.check_pages(layer, truth["pages"])
        self.assertEqual(layer.ranges(), [(0, 2 * PAGE), (0x100 * PAGE, 3 * PAGE), (0x1000 * PAGE, PAGE)])
        self.assertAbsent(layer, 2 * PAGE)                       # hole right after a run
        self.assertAbsent(layer, 0x50 * PAGE)                    # the zero-page run maps nothing
        self.assertAbsent(layer, 0x102 * PAGE + 4090, 16)        # a read straddling the end of a run
        self.assertEqual(layer.read(0x102 * PAGE + 4090, 16, pad=True), pages[0x102][4090:] + b"\x00" * 10)
        self.assertEqual(layer.read(0x100 * PAGE + 4000, 200), (pages[0x100] + pages[0x101])[4000:4200])
        f = truth["fields"]
        self.assertEqual((meta["format"], meta["dump_type"], meta["dump_type_value"]), ("windump", "full", 1))
        self.assertEqual(meta["directory_table_base"], f["dtb"])
        self.assertEqual(meta["ps_active_process_head"], f["ps_active_process_head"])
        self.assertEqual(meta["ps_loaded_module_list"], f["ps_loaded_module_list"])
        self.assertEqual(meta["kd_debugger_data_block"], f["kd_debugger_data_block"])
        self.assertEqual((meta["machine"], meta["number_processors"]), ("x64", f["ncpu"]))
        self.assertEqual((meta["bugcheck_code"], meta["bugcheck_parameters"]), (0x161, [1, 2, 3, 4]))
        self.assertEqual((meta["major_version"], meta["minor_version"]), (0xF, 26100))
        self.assertEqual(meta["system_time"], filetime_iso(f["system_time"]))
        self.assertEqual(meta["comment"], "keto synthetic live dump")
        self.assertEqual(meta["header_physical_runs"], runs)
        self.assertEqual(meta["physical_runs"], layer.ranges())
        self.assertEqual(meta["warnings"], [])

    def bitmap_pfns(self):
        rng = random.Random(9)
        pfns = {0, 7, 8, 15, 16} | set(range(64, 64 + 8 * 6)) | set(range(300, 333))
        pfns |= {rng.randrange(400, 3000) for _ in range(300)}
        return sorted(pfns)

    def test_bitmap_dumps(self):
        pfns = self.bitmap_pfns()
        for dump_type, sig, name in ((5, b"SDMP", "bitmap_kernel"), (5, b"FDMP", "bitmap_full"),
                                     (6, b"SDMP", "live_kernel_bitmap"), (6, b"FDMP", "live_kernel_bitmap")):
            path = tmp("bmp_%d_%s.dmp" % (dump_type, sig.decode()))
            truth = sw.write_crash_dump(path, pages_of(pfns, sig), dump_type, bmp_signature=sig)
            layer, meta = self.open(path)
            self.check_pages(layer, truth["pages"])
            self.assertEqual((meta["dump_type"], meta["bitmap_signature"]), (name, sig.decode()))
            self.assertEqual(meta["present_pages"], len(pfns))
            self.assertEqual(meta["warnings"], [])
            self.assertAbsent(layer, 1 * PAGE)
            self.assertAbsent(layer, 3001 * PAGE)

    def test_bitmap_bit_order_hand_assembled(self):
        """kdmp-parser layout, assembled by hand: HEADER64 'PAGE' 'DU64' with DumpType (0xF98) = 5, BMP_HEADER64 at
        0x2000 ('SDMP', 'DUMP', FirstPage @0x20, TotalPresentPages @0x28, Pages @0x30, bitmap @0x38). Bit i of the
        bitmap is PFN i (LSB first): byte 0 = 0b00000101 -> PFNs 0 and 2, byte 1 = 0x80 -> PFN 15."""
        hdr = bytearray(b"PAGE" * 2048)
        hdr[0:8] = b"PAGEDU64"
        struct.pack_into("<I", hdr, 0xF98, 5)
        bmp = b"SDMP" + b"DUMP" + b"\x00" * 24 + struct.pack("<QQQ", 0x3000, 3, 16) + bytes([0b00000101, 0x80])
        body = bytes(hdr) + bmp.ljust(0x1000, b"\x00") + b"".join(bytes([p]) * PAGE for p in (0, 2, 15))
        path = tmp("hand.dmp")
        with open(path, "wb") as fh:
            fh.write(body)
        layer, meta = self.open(path)
        self.assertEqual(layer.ranges(), [(0, PAGE), (2 * PAGE, PAGE), (15 * PAGE, PAGE)])
        self.assertEqual([layer.read(p * PAGE, 1) for p in (0, 2, 15)], [b"\x00", b"\x02", b"\x0f"])
        self.assertEqual(meta["first_page_offset"], 0x3000)

    def test_bitmap_pages_not_multiple_of_8(self):
        # kdmp-parser's documented example: Pages = 137 -> an 18-byte bitmap of which only 1 bit of the last byte
        # counts; a set bit beyond Pages must be ignored
        pfns = [0, 100, 136]
        path = tmp("bmp137.dmp")
        sw.write_crash_dump(path, pages_of(pfns + [137, 139]), 5, bitmap_pages=137)
        with open(path, "r+b") as fh:                          # set bits 137 and 139 (beyond Pages) by hand
            fh.seek(0x2038 + 17)
            b = fh.read(1)[0]
            fh.seek(0x2038 + 17)
            fh.write(bytes([b | 0b1010]))
        layer, meta = self.open(path)
        self.assertEqual(meta["bitmap_pages"], 137)
        self.assertEqual(sorted(s // PAGE for s, _l in layer.ranges()), pfns)

    def test_rdmp_dumps(self):
        pfns = [1, 2, 3, 10, 11, 0x4000, 0x4001, 0x4002, 0x4003]
        for dump_type, name in ((8, "kernel_memory"), (9, "kernel_and_user_memory"), (10, "complete_memory")):
            path = tmp("rdmp%d.dmp" % dump_type)
            truth = sw.write_crash_dump(path, pages_of(pfns, b"r%d" % dump_type), dump_type)
            layer, meta = self.open(path)
            self.check_pages(layer, truth["pages"])
            self.assertEqual(meta["dump_type"], name)
            self.assertEqual(meta["first_page_offset"], 0x2020 + meta["rdmp_metadata_size"])
            self.assertEqual(meta["warnings"], [])

    def test_refused_variants(self):
        pages = pages_of([0, 1])
        cases = ((4, UnsupportedError, "triage"), (2, UnsupportedError, "legacy kernel summary"),
                 (0x55, UnsupportedError, "unknown crash dump DumpType 0x55"))
        for dump_type, exc, text in cases:
            path = tmp("type%x.dmp" % dump_type)
            sw.write_crash_dump(path, pages, dump_type)
            self.assertEqual(detect(path), "windump")
            with self.assertRaises(exc) as cm:
                open_memory_image("physical", path)
            self.assertIn(text, str(cm.exception))
        path = tmp("x86.dmp")
        sw.write_crash_dump(path, pages, 1)
        with open(path, "r+b") as fh:
            fh.write(b"PAGEDUMP")
        self.assertEqual(detect(path), "windump")
        with self.assertRaises(UnsupportedError) as cm:
            open_memory_image("physical", path)
        self.assertIn("32-bit", str(cm.exception))
        path = tmp("badvalid.dmp")
        sw.write_crash_dump(path, pages, 5, bmp_valid=b"XXXX")
        with self.assertRaises(FormatError) as cm:
            open_memory_image("physical", path)
        self.assertIn("ValidDump", str(cm.exception))
        path = tmp("pagefill.dmp")                               # DumpType 1 without a run list
        sw.write_crash_dump(path, {}, 1, runs=[])
        with self.assertRaises(FormatError) as cm:
            open_memory_image("physical", path)
        self.assertIn("'PAGE' fill", str(cm.exception))

    def test_undocumented_bitmap_signature(self):
        pfns = [0, 5, 6, 7]
        path = tmp("dmp_.dmp")
        truth = sw.write_crash_dump(path, pages_of(pfns), 6, bmp_signature=b"DMP_")
        layer, meta = self.open(path)
        self.check_pages(layer, truth["pages"])
        self.assertEqual(meta["dump_type"], "bitmap_unknown_signature")
        self.assertTrue(any("not a documented value" in w for w in meta["warnings"]))
        with open(path, "r+b") as fh:                            # break TotalPresentPages: now refused
            fh.seek(0x2028)
            fh.write(struct.pack("<Q", 99))
        with self.assertRaises(UnsupportedError) as cm:
            open_memory_image("physical", path)
        self.assertIn("'DMP_'", str(cm.exception).replace("b'DMP_'", "'DMP_'"))

    def test_truncated_dump_keeps_what_is_there(self):
        pfns = list(range(10))
        path = tmp("trunc.dmp")
        truth = sw.write_crash_dump(path, pages_of(pfns), 5, truncate=PAGE + 100)
        layer, meta = self.open(path)
        self.assertTrue(meta["truncated"])
        self.assertTrue(any("truncated" in w for w in meta["warnings"]))
        self.check_pages(layer, {p: truth["pages"][p] for p in range(8)})   # page 8 is partial, 9 missing
        self.assertAbsent(layer, 8 * PAGE)

    def test_16gib_bitmap_opens_in_seconds(self):
        """A bitmap for 16 GiB (4M pages, fragmented every 64 pages) over a file holding only the first pages:
        opening parses the whole bitmap and builds the runs without per-page objects."""
        nbits = (16 << 30) // PAGE
        bitmap = bytearray(b"\xff" * (nbits // 8))
        for i in range(0, len(bitmap), 8):
            bitmap[i] = 0x7F                                     # PFN 64k+7 absent: 65536 runs
        hdr = bytearray(b"PAGE" * 2048)
        hdr[0:8] = b"PAGEDU64"
        struct.pack_into("<I", hdr, 0xF98, 5)
        first = (0x2038 + len(bitmap) + PAGE - 1) // PAGE * PAGE
        present = nbits - nbits // 64
        bmp = b"FDMP" + b"DUMP" + b"\x00" * 24 + struct.pack("<QQQ", first, present, nbits)
        path = tmp("16g.dmp")
        with open(path, "wb") as fh:
            fh.write(hdr + bmp + bitmap)
            fh.write(b"\x00" * (first - fh.tell()))
            fh.write(b"\x11" * (16 * PAGE))
        t = time.perf_counter()
        layer, meta = self.open(path)
        elapsed = time.perf_counter() - t
        self.assertLess(elapsed, 5.0)
        self.assertTrue(meta["truncated"])
        self.assertEqual(meta["present_pages"], 16)
        self.assertEqual(layer.ranges(), [(0, 7 * PAGE), (8 * PAGE, 9 * PAGE)])
        t = time.perf_counter()
        starts, ends = windump.bitmap_runs(bitmap, nbits)
        self.assertEqual(len(starts), nbits // 64 + 1)           # [0, 7), then one run per 64-page stride
        self.assertEqual((starts[:2].tolist(), ends[:2].tolist()), ([0, 8], [7, 71]))
        self.assertLess(time.perf_counter() - t, 5.0)
        worst = bytes([0x55]) * (nbits // 64)                    # every other page of 1 GiB: all partial bytes
        t = time.perf_counter()
        self.assertEqual(len(windump.bitmap_runs(worst, nbits // 8)[0]), nbits // 16)
        self.assertLess(time.perf_counter() - t, 10.0)


# -- ELF cores --------------------------------------------------------------------------------------------------------
class ElfCoreTests(OpenMixin, unittest.TestCase):
    def segments(self, layout):
        segs, truth = [], {}
        for base_pfn, count in layout:
            data = b"".join(sw.page_content(p, b"elf") for p in range(base_pfn, base_pfn + count))
            segs.append((base_pfn * PAGE, data))
            truth.update({p: sw.page_content(p, b"elf") for p in range(base_pfn, base_pfn + count)})
        return segs, truth

    def test_qemu_elf64(self):
        # below 640 KiB, 1 MiB.., and RAM above the PCI hole at 4 GiB; the last segment's p_memsz exceeds p_filesz
        segs, truth = self.segments([(0, 16), (0x100, 32), (0x100000, 8)])
        path = tmp("qemu64.elf")
        sw.write_qemu_core(path, segs, [0x1AD000, 0x2BE000], memsz_extra=(0, 0, 0x3000))
        self.assertEqual(detect(path), "elfcore")
        layer, meta = self.open(path)
        self.check_pages(layer, truth)
        self.assertEqual((meta["producer"], meta["elf_class"], meta["qemu_paging"]), ("qemu", 64, False))
        self.assertEqual([c["cr3"] for c in meta["cpus"]], [0x1AD000, 0x2BE000])
        self.assertEqual(meta["cr3"], 0x1AD000)
        self.assertEqual(meta["absent_tail_bytes"], 0x3000)
        self.assertAbsent(layer, 0x100008 * PAGE)                # p_memsz beyond p_filesz is not in the file
        self.assertAbsent(layer, 0xC0000)                        # between segments

    def test_qemu_paging_mode_aliases(self):
        # dump-guest-memory -p: p_vaddr = guest virtual; two virtual mappings of the same physical pages
        segs, truth = self.segments([(0x200, 4), (0x200, 2), (0x300, 1)])
        path = tmp("qemu_paging.elf")
        sw.write_qemu_core(path, segs, [0x5000], vaddrs=[0xFFFF800000200000, 0x7FF000000000, 0xFFFF800000300000])
        layer, meta = self.open(path)
        self.check_pages(layer, truth)
        self.assertTrue(meta["qemu_paging"])
        self.assertEqual(meta["aliased_bytes"], 2 * PAGE)

    def test_qemu_elf32_pn_xnum(self):
        segs, truth = self.segments([(0, 4), (0x10, 4)])
        path = tmp("qemu32.elf")
        sw.write_qemu_core(path, segs, [0x9000], elf_class=32, xnum=True)
        layer, meta = self.open(path)
        self.check_pages(layer, truth)
        self.assertEqual((meta["elf_class"], meta["load_segments"], meta["cr3"]), (32, 2, 0x9000))

    def test_virtualbox_core(self):
        ram0 = b"".join(sw.page_content(p, b"vb") for p in range(8))
        ram1 = b"".join(sw.page_content(p, b"vb") for p in range(0x100, 0x108))
        path = tmp("vbox.core")
        sw.write_vbox_core(path, [(0, len(ram0), ram0), (0xE0000000, 0x10000, None), (0x100000, len(ram1), ram1)],
                           [0x1AB000, 0x1AC000])
        layer, meta = self.open(path)
        truth = {p: sw.page_content(p, b"vb") for p in list(range(8)) + list(range(0x100, 0x108))}
        self.check_pages(layer, truth)
        self.assertEqual(meta["producer"], "virtualbox")
        self.assertEqual([c["cr3"] for c in meta["cpus"]], [0x1AB000, 0x1AC000])
        self.assertEqual((meta["vbox_cpus"], meta["vbox_revision"]), (2, 165100))
        self.assertAbsent(layer, 0xE0000000)                     # MMIO range: p_filesz 0

    def test_documented_note_layouts(self):
        """Hand-assembled from the producers' headers: QEMUCPUState cr[3] at byte 8 + 18*8 + 10*24 + 3*8 = 416;
        DBGFCORECPU cr3 at 18*8 + 6*24 + 2*8 = 304; NT_VBOXCPU = 0xb01, 'VBCPU' with n_namesz 5 (no NUL)."""
        qstate = bytearray(440)
        struct.pack_into("<II", qstate, 0, 1, 440)
        struct.pack_into("<Q", qstate, 416, 0xABCDE000)
        vcpu = bytearray(0x400)
        struct.pack_into("<Q", vcpu, 304, 0x12345000)
        note = lambda name, t, d, nsz: struct.pack("<III", nsz, len(d), t) + name.ljust((nsz + 4) & ~3, b"\x00") + d
        for nname, ntype, desc, nsz, want in ((b"QEMU", 0, bytes(qstate), 5, 0xABCDE000),
                                              (b"VBCPU", 0xB01, bytes(vcpu), 5, 0x12345000)):
            notes = note(nname, ntype, desc, nsz)
            data = b"\x5a" * PAGE
            eh = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01", 4, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
            off = 64 + 2 * 56
            ph = struct.pack("<IIQQQQQQ", 4, 0, off, 0, 0, len(notes), len(notes), 0)
            ph += struct.pack("<IIQQQQQQ", 1, 0, off + len(notes), 0, 0x7000, PAGE, PAGE, 0)
            path = tmp("hand_%s.elf" % nname.decode())
            with open(path, "wb") as fh:
                fh.write(eh + ph + notes + data)
            layer, meta = self.open(path)
            self.assertEqual(meta["cr3"], want)
            self.assertEqual(layer.read(0x7000, 4), b"\x5a" * 4)

    def test_process_core_refused(self):
        path = tmp("process.core")
        segs = [(0, b"\x01" * PAGE), (0, b"\x02" * PAGE)]
        sw.write_qemu_core(path, segs, [], vaddrs=[0x400000, 0x7FFE0000])
        with self.assertRaises(UnsupportedError) as cm:
            open_memory_image("physical", path)
        self.assertIn("process core", str(cm.exception))


# -- VMware -----------------------------------------------------------------------------------------------------------
class VmwareTests(OpenMixin, unittest.TestCase):
    def memory(self, npages, salt=b"vm"):
        return b"".join(sw.page_content(i, salt) for i in range(npages))

    def mapped(self, regions, salt=b"vm"):
        """{physical pfn: content} implied by regions (ppn, page_num, pages) over memory page contents."""
        return {ppn + k: sw.page_content(pnum + k, salt) for ppn, pnum, size in regions for k in range(size)}

    def test_regions_above_pci_hole(self):
        d = tempfile.mkdtemp(dir=TMP)
        regions = [(0, 0, 48), (0x100000, 48, 16)]               # 192 KiB low, 64 KiB at 4 GiB
        files = sw.write_vmware(d, "Win10-a1b2", regions, self.memory(64), cr3s=[0x1AA000, 0x1BB000])
        truth = self.mapped(regions)
        for opened in (files["state"], files["vmem"]):           # either file finds its companion
            self.assertEqual(detect(opened), "vmware")
            layer, meta = self.open(opened)
            self.check_pages(layer, truth)
            self.assertEqual(layer.read(0x100000000, 16), sw.page_content(48, b"vm")[:16])
            self.assertAbsent(layer, 48 * PAGE)
            self.assertEqual((meta["state_file"], meta["vmem_file"]), (files["state"], files["vmem"]))
            self.assertEqual((meta["mapping"], meta["memory_embedded"]), ("regions", False))
            self.assertEqual([c["cr3"] for c in meta["cpus"]], [0x1AA000, 0x1BB000])
            self.assertEqual(meta["cr3"], 0x1AA000)
            self.assertEqual(meta["warnings"], [])

    def test_three_regions_with_gaps(self):
        # each region's file position comes from its own regionPageNum, not from accumulated holes
        d = tempfile.mkdtemp(dir=TMP)
        regions = [(0, 0, 16), (0x40, 20, 8), (0x100000, 30, 6)]   # memory pages 16..19 and 28..29 are unmapped
        files = sw.write_vmware(d, "three", regions, self.memory(36), cr3s=[0x7000], cr_style="values")
        layer, meta = self.open(files["vmem"])
        self.check_pages(layer, self.mapped(regions))
        self.assertEqual(meta["cpus"][0]["cr3"], 0x7000)

    def test_embedded_memory_old_magic(self):
        d = tempfile.mkdtemp(dir=TMP)
        regions = [(0, 0, 8), (0x100, 8, 4)]
        files = sw.write_vmware(d, "snap-1", regions, self.memory(12), cr3s=[0xA000], ext=".vmsn",
                                magic=0xBED2BED0, embedded=True)
        layer, meta = self.open(files["state"])
        self.check_pages(layer, self.mapped(regions))
        self.assertTrue(meta["memory_embedded"])
        self.assertEqual((meta["magic"], meta["cr3"]), (0xBED2BED0, 0xA000))

    def test_flat_memory_without_regions(self):
        d = tempfile.mkdtemp(dir=TMP)
        files = sw.write_vmware(d, "small", [], self.memory(10), cr3s=[0x3000])
        layer, meta = self.open(files["state"])
        self.check_pages(layer, {i: sw.page_content(i, b"vm") for i in range(10)})
        self.assertEqual(meta["mapping"], "flat")

    def test_lone_vmem_falls_back_to_flat(self):
        d = tempfile.mkdtemp(dir=TMP)
        files = sw.write_vmware(d, "lonely", [(0, 0, 4)], self.memory(4))
        os.remove(files["state"])
        layer, meta = self.open(files["vmem"])
        self.assertEqual((meta["format"], meta["mapping"], meta["state_file"]), ("vmware", "flat", None))
        self.assertTrue(any("no .vmss/.vmsn companion" in w for w in meta["warnings"]))
        self.assertEqual(layer.read(3 * PAGE, 8), sw.page_content(3, b"vm")[:8])

    def test_compressed_memory_refused(self):
        d = tempfile.mkdtemp(dir=TMP)
        files = sw.write_vmware(d, "comp", [(0, 0, 4)], self.memory(4), embedded=True, compressed_memory=True)
        with self.assertRaises(UnsupportedError) as cm:
            open_memory_image("physical", files["state"])
        self.assertIn("compressed", str(cm.exception))

    def test_documented_tag_encoding(self):
        """crash-utility vmware_vmss.h by hand: header {id 0xbed2bed2, version, numgroups}, cptgroupdesc
        {name[64], position, size}, TAG = name length << 8 | index count << 6 | value size; 'regionsCount' with a
        4-byte value is tag 0x0C04 (bytes 04 0c); a block tag (value size 63) carries u64 sizes and a u16 pad."""
        tag = lambda name, nidx, size: struct.pack("<H", (len(name) << 8) | (nidx << 6) | size) + name
        mem = (tag(b"regionsCount", 0, 4) + struct.pack("<I", 1)
               + tag(b"regionPageNum", 1, 4) + struct.pack("<II", 0, 0)
               + tag(b"regionPPN", 1, 4) + struct.pack("<II", 0, 0x200)
               + tag(b"regionSize", 1, 4) + struct.pack("<II", 0, 2) + b"\x00\x00")
        cpu = (tag(b"CR64", 1, 63) + struct.pack("<I", 0) + struct.pack("<QQH", 72, 72, 2) + b"\x00\x00"
               + struct.pack("<9Q", 1, 2, 3, 0xCAFE000, 5, 6, 7, 8, 9) + b"\x00\x00")
        self.assertEqual(mem[:2], b"\x04\x0c")
        state = (struct.pack("<III", 0xBED2BED2, 8, 2) + struct.pack("<64sQQ", b"memory", 12 + 160, len(mem))
                 + struct.pack("<64sQQ", b"cpu", 12 + 160 + len(mem), len(cpu)) + mem + cpu)
        d = tempfile.mkdtemp(dir=TMP)
        with open(os.path.join(d, "hand.vmss"), "wb") as fh:
            fh.write(state)
        with open(os.path.join(d, "hand.vmem"), "wb") as fh:
            fh.write(b"\x01" * PAGE + b"\x02" * PAGE)
        st = vmware.parse_state(os.path.join(d, "hand.vmss"))
        self.assertEqual(st["tags"]["memory"][("regionPPN", (0,))][1], 0x200)
        layer, meta = self.open(os.path.join(d, "hand.vmss"))
        self.assertEqual(layer.ranges(), [(0x200 * PAGE, 2 * PAGE)])
        self.assertEqual(layer.read(0x201 * PAGE, 2), b"\x02\x02")
        self.assertEqual(meta["cr3"], 0xCAFE000)


# -- hiberfil.sys ------------------------------------------------------------------------------------------------------
def hiber_sets(salt=b""):
    """Boot and kernel restoration sets with every codec, multi-descriptor sets, out-of-order PFNs and a full
    16-page (64 KiB) set; returns (boot_sets, kernel_sets, pages)."""
    boot = [([(0x10, 1)], "stored"), ([(0x20, 4), (0x30, 2)], "xpress"), ([(0x40, 16)], "huffman"),
            ([(0x80, 3)], "xpress"), ([(0x18, 2), (0x11, 1)], "huffman")]
    kernel = [([(0x1000, 16)], "xpress"), ([(0x900, 5), (0x905, 5), (0x2000, 6)], "huffman"),
              ([(0x3000, 2)], "stored"), ([(0x50, 8)], "xpress"), ([(0x10000, 16)], "huffman")]
    pfns = [f + k for sets in (boot, kernel) for descs, _c in sets for f, n in descs for k in range(n)]
    return boot, kernel, pages_of(pfns, salt)


class HiberTests(OpenMixin, unittest.TestCase):
    def build(self, name, build="win10_22h2", **kw):
        boot, kernel, pages = hiber_sets(name.encode())
        path = tmp(name)
        truth = sw.write_hiber(path, kw.pop("boot", boot), kw.pop("kernel", kernel), pages, build=build, **kw)
        return path, truth

    def test_every_build_layout(self):
        expect = {"win8": "windows-8/8.1", "win10_1511": "windows-10-1507/1511", "win10_1607": "windows-10-1607",
                  "win10_22h2": "windows-10-1703..windows-11-23h2", "win11_23h2": "windows-10-1703..windows-11-23h2",
                  "win11_24h2": "windows-11-24h2/25h2", "win11_26h2": "windows-11-26h2"}
        for build, layout in expect.items():
            path, truth = self.build("hiber_%s.sys" % build, build=build, cr3=0x1AD000 + 0x1000 * len(build))
            self.assertEqual(detect(path), "hiber")
            layer, meta = self.open(path)
            self.check_pages(layer, truth["pages"])
            self.assertEqual((meta["layout"], meta["layout_inferred"]), (layout, False), build)
            self.assertEqual(meta["cr3"], 0x1AD000 + 0x1000 * len(build))
            self.assertEqual(meta["kernel_pages_processed"], truth["kernel_pages"])
            self.assertEqual(meta["num_pages_for_loader"], truth["boot_pages"])
            self.assertEqual(meta["first_kernel_restore_page"], truth["first_kernel"])
            self.assertEqual(set(meta["codecs"]), {"stored", "xpress", "xpress_huffman"})
            self.assertEqual(meta["warnings"], [], build)
            self.assertAbsent(layer, 0x12 * PAGE)
            self.assertAbsent(layer, 0x10010 * PAGE)
            self.assertEqual(layer.read(0x41 * PAGE + 4000, 200),
                             (truth["pages"][0x41] + truth["pages"][0x42])[4000:4200])   # inside a set

    @unittest.skipUnless(NT, "needs Windows ntdll (RtlCompressBuffer)")
    def test_ntdll_compressed_sets(self):
        path, truth = self.build("hiber_ntdll.sys", xpress=lambda d: sw.ntdll_compress(3, d),
                                 huffman=lambda d: sw.ntdll_compress(4, d, sw.COMPRESSION_ENGINE_MAXIMUM))
        layer, meta = self.open(path)
        self.check_pages(layer, truth["pages"])
        self.assertEqual(meta["decode_problems"], [])

    def test_hand_assembled_set(self):
        """Sylve et al.: set header bits 0-7 descriptor count, next 22 bits size, bit 31 Huffman; descriptor bits
        0-3 = pages - 1, the rest the PFN; stored when size == pages x 4096. Vergilius (Windows 10 1703+ x64):
        NumPagesForLoader 0x58, FirstBootRestorePage 0x68, FirstKernelRestorePage 0x70, PerfInfo 0x88 with
        BootPagesProcessed +0x1a0 and KernelPagesProcessed +0x1a8; 'HIBR' = 0x52424948."""
        h = bytearray(2 * PAGE)
        struct.pack_into("<I", h, 0, 0x52424948)
        struct.pack_into("<I", h, 0x0C, 0x3E0)
        struct.pack_into("<I", h, 0x18, PAGE)
        struct.pack_into("<QQQQ", h, 0x58, 2, 0, 2, 0)
        struct.pack_into("<Q", h, 0x88 + 0x1A0, 2)
        set_hdr = 1 | ((2 * PAGE) << 8)
        self.assertEqual(struct.pack("<I", set_hdr), bytes.fromhex("01002000"))
        body = h + struct.pack("<IQ", set_hdr, (0x1234 << 4) | 1) + b"\xaa" * PAGE + b"\xbb" * PAGE
        path = tmp("hand_hiber.sys")
        with open(path, "wb") as fh:
            fh.write(body)
        layer, meta = self.open(path)
        self.assertEqual(layer.ranges(), [(0x1234 * PAGE, 2 * PAGE)])
        self.assertEqual(layer.read(0x1235 * PAGE, 2), b"\xbb\xbb")
        self.assertEqual(meta["codecs"], {"stored": 1})

    def test_unknown_length_self_is_inferred(self):
        path, truth = self.build("hiber_unknown.sys", build="win11_24h2", length_self=0x777)
        layer, meta = self.open(path)
        self.check_pages(layer, truth["pages"])
        self.assertEqual((meta["layout"], meta["layout_inferred"]), ("windows-11-24h2/25h2", True))
        self.assertTrue(any("LengthSelf 0x777" in w for w in meta["warnings"]))

    def test_length_self_match_with_moved_counter(self):
        # LengthSelf of 24H2 (0x4d8) but KernelPagesProcessed where the 26H2 layout keeps it (0x250)
        path, truth = self.build("hiber_moved.sys", build="win11_26h2", length_self=0x4D8)
        layer, meta = self.open(path)
        self.check_pages(layer, truth["pages"])
        self.assertEqual((meta["layout"], meta["layout_inferred"]), ("windows-11-26h2", True))
        self.assertTrue(any("names the windows-11-24h2/25h2 layout" in w for w in meta["warnings"]))

    def test_codec_flag_mismatch_is_decoded_and_reported(self):
        boot = [([(0x10, 4)], "huffman")]
        pages = pages_of(range(0x10, 0x14), b"flag")
        path = tmp("hiber_flag.sys")
        truth = sw.write_hiber(path, boot, [], pages)
        with open(path, "r+b") as fh:                            # clear the Huffman bit (31) of the only set
            fh.seek(2 * PAGE + 3)
            b = fh.read(1)[0]
            fh.seek(2 * PAGE + 3)
            fh.write(bytes([b & 0x7F]))
        layer, meta = self.open(path)
        self.assertEqual(meta["codecs"], {"xpress": 1})
        self.check_pages(layer, truth["pages"])
        self.assertTrue(any("flagged xpress but decodes as xpress_huffman" in p for p in meta["decode_problems"]))

    def test_signatures(self):
        path, _t = self.build("hiber_wake.sys", signature=b"WAKE", wipe_after_header=True)
        self.assertEqual(detect(path), "hiber")
        with self.assertRaises(UnsupportedError) as cm:
            open_memory_image("physical", path)
        self.assertIn("'WAKE'", str(cm.exception))
        for sig, text in ((b"RSTR", "'RSTR'"), (b"WAKE", "'WAKE'"), (b"HORM", None)):
            path, truth = self.build("hiber_%s.sys" % sig.decode(), signature=sig)
            layer, meta = self.open(path)
            self.check_pages(layer, truth["pages"])
            self.assertEqual(meta["signature"], sig.decode())
            if text:
                self.assertTrue(any(text in w for w in meta["warnings"]), sig)

    def test_refused_variants(self):
        path, _t = self.build("hiber_legacy.sys", signature=b"hibr")
        with self.assertRaises(UnsupportedError) as cm:
            open_memory_image("physical", path)
        self.assertIn("XP-7", str(cm.exception))
        path = tmp("hiber_legacy_upper.sys")                     # 'HIBR' but table pages + xpress blocks
        with open(path, "wb") as fh:
            h = bytearray(4 * PAGE)
            h[0:4] = b"HIBR"
            struct.pack_into("<I", h, 0x18, PAGE)
            h[3 * PAGE:3 * PAGE + 8] = b"\x81\x81xpress"
            fh.write(h)
        with self.assertRaises(UnsupportedError) as cm:
            open_memory_image("physical", path)
        self.assertIn("XP-7", str(cm.exception))
        path, _t = self.build("hiber_x86.sys")
        with open(path, "r+b") as fh:                            # x86 keeps PageSize at 0x14
            fh.seek(0x14)
            fh.write(struct.pack("<II", PAGE, 0))
        with self.assertRaises(UnsupportedError) as cm:
            open_memory_image("physical", path)
        self.assertIn("32-bit", str(cm.exception))
        path, truth = self.build("hiber_corrupt.sys")
        with open(path, "r+b") as fh:                            # descriptor count 0 in the first set
            fh.seek(2 * PAGE)
            fh.write(b"\x00")
        with self.assertRaises(FormatError) as cm:
            open_memory_image("physical", path)
        self.assertIn("page descriptors", str(cm.exception))

    def test_restoration_set_boundaries(self):
        # the boot set ends exactly on its last page count; the kernel set starts on its own page after a gap
        boot = [([(0x100, 16)], "xpress"), ([(0x200, 16)], "huffman")]
        kernel = [([(0x300, 1)], "stored")]
        pages = pages_of([0x100 + k for k in range(16)] + [0x200 + k for k in range(16)] + [0x300], b"b")
        path = tmp("hiber_bound.sys")
        truth = sw.write_hiber(path, boot, kernel, pages, kernel_gap_pages=7)
        layer, meta = self.open(path)
        self.check_pages(layer, truth["pages"])
        self.assertEqual((meta["num_pages_for_loader"], meta["kernel_pages_processed"]), (32, 1))
        with open(path, "r+b") as fh:                            # claim one page more than the boot chain holds
            fh.seek(0x58)
            fh.write(struct.pack("<Q", 33))
        with self.assertRaises(FormatError):
            open_memory_image("physical", path)

    def test_duplicate_pfn_kernel_wins(self):
        # PFN 0x11 is in the boot set and, with newer data, in the kernel set (restored later by the kernel)
        boot = [([(0x10, 2)], "xpress")]
        kernel = [([(0x11, 1)], "stored"), ([(0x20, 1)], "huffman")]
        pages = pages_of([0x10, 0x11, 0x20], b"dup")
        path = tmp("hiber_dup.sys")
        truth = sw.write_hiber(path, boot, kernel, pages, kernel_pages={**pages, 0x11: b"\xee" * PAGE})
        layer, meta = self.open(path)
        self.check_pages(layer, truth["pages"])
        self.assertEqual(meta["duplicate_pages"], 1)
        self.assertEqual(layer.read(0x11 * PAGE, 4), b"\xee" * 4)
        self.assertTrue(any("more than one compression set" in w for w in meta["warnings"]))

    def test_decompression_is_cached(self):
        path, truth = self.build("hiber_cache.sys")
        layer, _meta = self.open(path)
        for _ in range(50):
            layer.read(0x1000 * PAGE + 123, 4000)
        self.assertEqual(layer.decompressions, 1)
        rng = random.Random(3)
        pfns = sorted(truth["pages"])
        for _ in range(500):
            p = rng.choice(pfns)
            self.assertEqual(layer.read(p * PAGE + 100, 50), truth["pages"][p][100:150])
        compressed = sum(1 for c in truth["codecs"] if c != "stored")
        self.assertLessEqual(layer.decompressions, compressed)
        self.assertEqual(sum(len(d) for _o, d, _n in layer.iter_chunks(1 << 20)), len(truth["pages"]) * PAGE)


# -- detection, open_memory_image, Context ---------------------------------------------------------------------------
class DetectionTests(OpenMixin, unittest.TestCase):
    def test_random_and_signature_prefixed_data_is_raw(self):
        rng = random.Random(42)
        for i in range(300):
            n = rng.choice((1, 7, 64, 511, 4096, 0x2100, 70000))
            data = bytes(rng.getrandbits(8) for _ in range(n))
            if i % 6 == 1:
                data = b"PAGE" + data                            # signature prefix, no 'DU64'/'DUMP'
            elif i % 6 == 2:
                data = b"\x7fELF" + data
            elif i % 6 == 3:
                data = b"HIBR" + data
            elif i % 6 == 4:
                data = struct.pack("<I", 0xBED2BED2) + data
            path = tmp("rand%d.bin" % i)
            with open(path, "wb") as fh:
                fh.write(data)
            self.assertIsNone(detect(path), (i, data[:16]))
        for n in (1, PAGE, 0x10000):
            path = tmp("zeros%d.bin" % n)
            with open(path, "wb") as fh:
                fh.write(b"\x00" * n)
            self.assertIsNone(detect(path))

    def test_existing_images(self):
        from keto.formats.container import write_lime
        from keto.testing.synth import build_all
        d = tempfile.mkdtemp(dir=TMP)
        build_all(d)
        self.assertIsNone(detect(os.path.join(d, "synthetic_vram.raw")))
        self.assertEqual(detect(os.path.join(d, "synthetic.keto")), "container")
        self.assertEqual(detect(os.path.join(d, "synthetic_host.lime")), "lime")
        self.assertIsNone(detect(os.path.join(HERE, "fixtures", "jit_sm89_probe.cubin")))   # ELF, not a core
        for name in os.listdir(os.path.join(HERE, "fixtures", "real")):
            self.assertIsNone(detect(os.path.join(HERE, "fixtures", "real", name)), name)
        lime = os.path.join(d, "h.lime")
        write_lime(lime, [(0x5000, b"\x42" * PAGE)])
        layer, meta = self.open(lime)
        self.assertEqual((meta["format"], layer.read(0x5000, 1)), ("lime", b"\x42"))
        layer, meta = self.open(os.path.join(d, "synthetic_vram.raw"))
        self.assertEqual(meta["format"], "raw")

    def test_context_integration(self):
        dump = tmp("ctx.dmp")
        truth = sw.write_crash_dump(dump, pages_of([3, 4]), 5)
        core = tmp("ctx.elf")
        sw.write_qemu_core(core, [(0x2000, sw.page_content(2, b"c"))], [0x4000])
        raw = tmp("ctx.raw")
        with open(raw, "wb") as fh:
            fh.write(b"\x00" * PAGE)
        with Context(image=dump, host_image=core) as c:
            self.assertEqual(c.primary_name, "physical")
            self.assertEqual(c.image_formats["physical"]["format"], "windump")
            self.assertEqual(c.primary.read(3 * PAGE, PAGE), truth["pages"][3])
            self.assertEqual(c.image_formats["sysmem"]["cr3"], 0x4000)
            self.assertEqual(c.layers["sysmem"].read(0x2000, PAGE), sw.page_content(2, b"c"))
        with Context(image=raw) as c:                            # raw: unchanged behaviour
            self.assertEqual((c.primary_name, sorted(c.layers), c.image_formats), ("vram", ["vram"], {}))
        with Context(host_image=raw) as c:
            self.assertEqual((sorted(c.layers), c.image_formats), (["sysmem"], {}))
        bad = tmp("ctx_x86.dmp")
        sw.write_crash_dump(bad, pages_of([1]), 1)
        with open(bad, "r+b") as fh:
            fh.write(b"PAGEDUMP")
        with self.assertRaises(UnsupportedError):                # recognised: refused, never opened as raw VRAM
            Context(image=bad)


if __name__ == "__main__":
    unittest.main()
