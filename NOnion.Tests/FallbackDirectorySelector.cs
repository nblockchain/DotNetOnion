using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace NOnion.Tests
{
    public static class FallbackDirectorySelector
    {
        static List<string> fallbackDirectories;

        static internal IPEndPoint GetRandomFallbackDirectory()
        {
            if (fallbackDirectories == null)
            {
                var urlToTorServerList = "https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/fallback_dirs.inc";
                using var webClient = new WebClient();
                var fetchedInfo = webClient.DownloadString(urlToTorServerList);

                var ipv4Pattern = "\"([0-9\\.]+)\\sorport=(\\S*)\\sid=(\\S*)\"";
                var matches = Regex.Matches(fetchedInfo, ipv4Pattern);

                fallbackDirectories = matches.Select(regMatch => $"{regMatch.Groups[1].Value}:{regMatch.Groups[2].Value}").ToList();
            }

            return
                IPEndPoint.Parse (
                    fallbackDirectories
                        .OrderBy(x => Guid.NewGuid())
                        .First()
                );
        }
    }
}
