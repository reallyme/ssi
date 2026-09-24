// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// The concatenated representation keeps the complete ISO 3166-1 alpha-2 set
// auditable without allocating or accepting syntactically valid private codes.
// The list was reviewed against the current ISO/TC 46 list on 2026-09-21.
const ISO_3166_ALPHA_2: &str = "ADAEAFAGAIALAMAOAQARASATAUAWAXAZBABBBDBEBFBGBHBIBJBLBMBNBOBQBRBSBTBVBWBYBZCACCCDCFCGCHCICKCLCMCNCOCRCUCVCWCXCYCZDEDJDKDMDODZECEEEGEHERESETFIFJFKFMFOFRGAGBGDGEGFGGGHGIGLGMGNGPGQGRGSGTGUGWGYHKHMHNHRHTHUIDIEILIMINIOIQIRISITJEJMJOJPKEKGKHKIKMKNKPKRKWKYKZLALBLCLILKLRLSLTLULVLYMAMCMDMEMFMGMHMKMLMMMNMOMPMQMRMSMTMUMVMWMXMYMZNANCNENFNGNINLNONPNRNUNZOMPAPEPFPGPHPKPLPMPNPRPSPTPWPYQARERORSRURWSASBSCSDSESGSHSISJSKSLSMSNSOSRSSSTSVSXSYSZTCTDTFTGTHTJTKTLTMTNTOTRTTTVTWTZUAUGUMUSUYUZVAVCVEVGVIVNVUWFWSYEYTZAZMZW";

pub(crate) fn is_iso_3166_alpha_2(value: &str) -> bool {
    value.len() == 2
        && value.bytes().all(|byte| byte.is_ascii_uppercase())
        && ISO_3166_ALPHA_2
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .any(|candidate| candidate.as_slice() == value.as_bytes())
}
