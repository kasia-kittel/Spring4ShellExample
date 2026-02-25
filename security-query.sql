SELECT
  CASE WHEN MALICIOUS = true THEN 'Malicious code detected 🚩'
       WHEN REACHABILITY = 'REACHABLE' AND EPSS_PERCENTAGE >= 60 THEN 'Reachable vulnerability with high EPSS% 🔴'
  ELSE ''
  END as reason,
  COUNT(*) AS count
FROM (
      SELECT
        *,
        CONCAT(REPLACE(ORGANIZATION, '-github-scans', ''), '/', LOWER(GITHUB_REPOSITORY)) AS normalized_repo
      FROM SECURITY.V_SECOPS_MEND_SUMMARY_TBL
    ) s
WHERE
  s.normalized_repo IN (${repoRaw:sqlstring})
  AND DATE(CREATE_DATE) = DATEADD(DAY, -1, CURRENT_DATE)
  AND 
  (FIX_DATE IS NOT NULL
  AND s.CVSS3_SEVERITY = 'critical'
  AND EPSS_PERCENTAGE >= 60
  AND REACHABILITY = 'REACHABLE')
  OR MALICIOUS = true
GROUP BY reason
ORDER BY reason;
