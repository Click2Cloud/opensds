// Copyright (c) 2019 The OpenSDS Authors.
//
//    Licensed under the Apache License, Version 2.0 (the "License"); you may
//    not use this file except in compliance with the License. You may obtain
//    a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//    License for the specific language governing permissions and limitations
//    under the License.
package ceph

import (
	"encoding/json"
	"fmt"

	"github.com/ceph/go-ceph/rados"
	log "github.com/golang/glog"
)

type MetricCli struct {
	conn *rados.Conn
}

func NewMetricCli() (*MetricCli, error) {

	conn, err := rados.NewConn()
	if err != nil {
		log.Error("when connecting to rados:", err)
		return nil, err
	}

	err = conn.ReadDefaultConfigFile()
	if err != nil {
		log.Error("file ReadDefaultConfigFile can't read", err)
		return nil, err
	}

	err = conn.Connect()
	if err != nil {
		log.Error("when connecting to ceph cluster:", err)
		return nil, err
	}

	return &MetricCli{
		conn,
	}, nil
}

type CephMetricStats struct {
	Name        string
	Value       string
	Unit        string
	Const_Label map[string]string
	AggrType    string
	Var_Label   map[string]string
	Help        string
}

type cephPoolStats struct {
	Pools []struct {
		Name  string `json:"name"`
		ID    int    `json:"id"`
		Stats struct {
			BytesUsed    json.Number `json:"bytes_used"`
			RawBytesUsed json.Number `json:"raw_bytes_used"`
			MaxAvail     json.Number `json:"max_avail"`
			Objects      json.Number `json:"objects"`
			DirtyObjects json.Number `json:"dirty"`
			ReadIO       json.Number `json:"rd"`
			ReadBytes    json.Number `json:"rd_bytes"`
			WriteIO      json.Number `json:"wr"`
			WriteBytes   json.Number `json:"wr_bytes"`
		} `json:"stats"`
	} `json:"pools"`
}

type cephClusterStats struct {
	Stats struct {
		TotalBytes      json.Number `json:"total_bytes"`
		TotalUsedBytes  json.Number `json:"total_used_bytes"`
		TotalAvailBytes json.Number `json:"total_avail_bytes"`
		TotalObjects    json.Number `json:"total_objects"`
	} `json:"stats"`
}

type cephPerfStat struct {
	PerfInfo []struct {
		ID    json.Number `json:"id"`
		Stats struct {
			CommitLatency json.Number `json:"commit_latency_ms"`
			ApplyLatency  json.Number `json:"apply_latency_ms"`
		} `json:"perf_stats"`
	} `json:"osd_perf_infos"`
}

type cephOSDDF struct {
	OSDNodes []struct {
		Name        json.Number `json:"name"`
		CrushWeight json.Number `json:"crush_weight"`
		Depth       json.Number `json:"depth"`
		Reweight    json.Number `json:"reweight"`
		KB          json.Number `json:"kb"`
		UsedKB      json.Number `json:"kb_used"`
		AvailKB     json.Number `json:"kb_avail"`
		Utilization json.Number `json:"utilization"`
		Variance    json.Number `json:"var"`
		Pgs         json.Number `json:"pgs"`
	} `json:"nodes"`

	Summary struct {
		TotalKB      json.Number `json:"total_kb"`
		TotalUsedKB  json.Number `json:"total_kb_used"`
		TotalAvailKB json.Number `json:"total_kb_avail"`
		AverageUtil  json.Number `json:"average_utilization"`
	} `json:"summary"`
}

type cephOSDDump struct {
	OSDs []struct {
		OSD json.Number `json:"osd"`
		Up  json.Number `json:"up"`
		In  json.Number `json:"in"`
	} `json:"osds"`
}

type cephHealthStats struct {
	Health struct {
		Summary []struct {
			Severity string `json:"severity"`
			Summary  string `json:"summary"`
		} `json:"summary"`
		OverallStatus string `json:"overall_status"`
		Status        string `json:"status"`
		Checks        map[string]struct {
			Severity string `json:"severity"`
			Summary  struct {
				Message string `json:"message"`
			} `json:"summary"`
		} `json:"checks"`
	} `json:"health"`
	OSDMap struct {
		OSDMap struct {
			NumOSDs        json.Number `json:"num_osds"`
			NumUpOSDs      json.Number `json:"num_up_osds"`
			NumInOSDs      json.Number `json:"num_in_osds"`
			NumRemappedPGs json.Number `json:"num_remapped_pgs"`
		} `json:"osdmap"`
	} `json:"osdmap"`
	PGMap struct {
		NumPGs                  json.Number `json:"num_pgs"`
		WriteOpPerSec           json.Number `json:"write_op_per_sec"`
		ReadOpPerSec            json.Number `json:"read_op_per_sec"`
		WriteBytePerSec         json.Number `json:"write_bytes_sec"`
		ReadBytePerSec          json.Number `json:"read_bytes_sec"`
		RecoveringObjectsPerSec json.Number `json:"recovering_objects_per_sec"`
		RecoveringBytePerSec    json.Number `json:"recovering_bytes_per_sec"`
		RecoveringKeysPerSec    json.Number `json:"recovering_keys_per_sec"`
		CacheFlushBytePerSec    json.Number `json:"flush_bytes_sec"`
		CacheEvictBytePerSec    json.Number `json:"evict_bytes_sec"`
		CachePromoteOpPerSec    json.Number `json:"promote_op_per_sec"`
		DegradedObjects         json.Number `json:"degraded_objects"`
		MisplacedObjects        json.Number `json:"misplaced_objects"`
		PGsByState              []struct {
			Count  float64 `json:"count"`
			States string  `json:"state_name"`
		} `json:"pgs_by_state"`
	} `json:"pgmap"`
}

type cephMonitorStats struct {
	Health struct {
		Health struct {
			HealthServices []struct {
				Mons []struct {
					Name         string      `json:"name"`
					KBTotal      json.Number `json:"kb_total"`
					KBUsed       json.Number `json:"kb_used"`
					KBAvail      json.Number `json:"kb_avail"`
					AvailPercent json.Number `json:"avail_percent"`
					StoreStats   struct {
						BytesTotal json.Number `json:"bytes_total"`
						BytesSST   json.Number `json:"bytes_sst"`
						BytesLog   json.Number `json:"bytes_log"`
						BytesMisc  json.Number `json:"bytes_misc"`
					} `json:"store_stats"`
				} `json:"mons"`
			} `json:"health_services"`
		} `json:"health"`
		TimeChecks struct {
			Mons []struct {
				Name    string      `json:"name"`
				Skew    json.Number `json:"skew"`
				Latency json.Number `json:"latency"`
			} `json:"mons"`
		} `json:"timechecks"`
	} `json:"health"`
	Quorum []int `json:"quorum"`
}

type cephTimeSyncStatus struct {
	TimeChecks map[string]struct {
		Health  string      `json:"health"`
		Latency json.Number `json:"latency"`
		Skew    json.Number `json:"skew"`
	} `json:"time_skew_status"`
}

func (cli *MetricCli) CollectPoolMetrics() ([]CephMetricStats, error) {
	returnMap := []CephMetricStats{}
	const_label := make(map[string]string)
	const_label["cluster"] = "ceph"
	cmd, err := json.Marshal(map[string]interface{}{
		"prefix": "df",
		"detail": "detail",
		"format": "json",
	})
	if err != nil {
		log.Errorf("cmd failed with %s\n", err)
	}

	buf, _, err := cli.conn.MonCommand(cmd)
	if err != nil {
	}

	pool_stats := &cephPoolStats{}
	if err := json.Unmarshal(buf, pool_stats); err != nil {
		log.Errorf("unmarshal error: %v", err)
	}

	for _, pool := range pool_stats.Pools {

		var_label := make(map[string]string)
		var_label["pool"] = pool.Name
		returnMap = append(returnMap, CephMetricStats{
			"used",
			pool.Stats.BytesUsed.String(),
			"bytes", const_label,
			"",
			var_label,
			"Capacity of the pool that is currently under use"})

		returnMap = append(returnMap, CephMetricStats{
			"raw_used",
			pool.Stats.RawBytesUsed.String(),
			"bytes", const_label,
			"",
			var_label,
			"Raw capacity of the pool that is currently under use, this factors in the size"})

		returnMap = append(returnMap, CephMetricStats{
			"available",
			pool.Stats.MaxAvail.String(),
			"bytes",
			const_label,
			"",
			var_label,
			"Free space for this ceph pool"})

		returnMap = append(returnMap, CephMetricStats{
			"objects",
			pool.Stats.Objects.String(),
			"",
			const_label,
			"total",
			var_label,
			"Total no. of objects allocated within the pool"})

		returnMap = append(returnMap, CephMetricStats{
			"dirty_objects",
			pool.Stats.DirtyObjects.String(),
			"",
			const_label,
			"total",
			var_label,
			"Total no. of dirty objects in a cache-tier pool"})

		returnMap = append(returnMap, CephMetricStats{
			"read", pool.Stats.ReadIO.String(),
			"",
			const_label,
			"total",
			var_label, "Total read i/o calls for the pool"})

		returnMap = append(returnMap, CephMetricStats{
			"read",
			pool.Stats.ReadBytes.String(),
			"bytes",
			const_label,
			"total",
			var_label, "Total read throughput for the pool"})

		returnMap = append(returnMap, CephMetricStats{
			"write",
			pool.Stats.WriteIO.String(),
			"", const_label,
			"total",
			var_label, "Total write i/o calls for the pool"})

		returnMap = append(returnMap, CephMetricStats{
			"write",
			pool.Stats.WriteBytes.String(),
			"bytes",
			const_label,
			"total",
			var_label, "Total write throughput for the pool"})
	}
	return returnMap, nil
}

func (cli *MetricCli) CollectClusterMetrics() ([]CephMetricStats, error) {
	var returnMap []CephMetricStats

	returnMap = []CephMetricStats{}
	const_label := make(map[string]string)
	const_label["cluster"] = "ceph"
	cmd, err := json.Marshal(map[string]interface{}{
		"prefix": "df",
		"detail": "detail",
		"format": "json",
	})
	if err != nil {
		log.Errorf("cmd failed with %s\n", err)
	}

	cmd, err = json.Marshal(map[string]interface{}{
		"prefix": "df",
		"detail": "detail",
		"format": "json",
	})
	if err != nil {
		// panic! because ideally in no world this hard-coded input
		// should fail.
		panic(err)
	}
	buf, _, err := cli.conn.MonCommand(cmd)
	if err != nil {
	}
	cluster_stats := &cephClusterStats{}
	if err := json.Unmarshal(buf, cluster_stats); err != nil {

		log.Fatalf("Unmarshal error: %v", err)
		// return
	}

	returnMap = append(returnMap,
		CephMetricStats{
			"capacity",
			cluster_stats.Stats.TotalBytes.String(),
			"bytes",
			const_label,
			"",
			nil,
			"Total capacity of the cluster"},
		CephMetricStats{
			"available",
			cluster_stats.Stats.TotalAvailBytes.String(),
			"bytes",
			const_label,
			"",
			nil,
			"Available space within the cluster"},
		CephMetricStats{
			"used",
			cluster_stats.Stats.TotalUsedBytes.String(),
			"bytes",
			const_label,
			"",
			nil,
			"Capacity of the cluster currently in use"},
		CephMetricStats{
			"objects",
			cluster_stats.Stats.TotalObjects.String(),
			"",
			const_label,
			"", nil, "No. of rados objects within the cluster"},
	)
	return returnMap, nil
}

func (cli *MetricCli) CollectPerfMetrics() ([]CephMetricStats, error) {
	var returnMap []CephMetricStats
	returnMap = []CephMetricStats{}
	const_label := make(map[string]string)
	const_label["cluster"] = "ceph"
	cmd, err := json.Marshal(map[string]interface{}{
		"prefix": "osd perf",
		"format": "json",
	})
	if err != nil {
		log.Errorf("cmd failed with %s\n", err)
	}
	buf, _, err := cli.conn.MonCommand(cmd)
	if err != nil {
		log.Errorf("unable to collect data from ceph osd perf")
	}
	osdPerf := &cephPerfStat{}
	if err := json.Unmarshal(buf, osdPerf); err != nil {
		log.Errorf("unmarshal failed")
	}

	for _, perfStat := range osdPerf.PerfInfo {
		var_label := make(map[string]string)

		osdID, err := perfStat.ID.Int64()
		if err != nil {
			log.Errorf("when collecting ceph cluster metrics")
		}
		var_label["osd"] = fmt.Sprintf("osd.%v", osdID)

		returnMap = append(returnMap,
			CephMetricStats{
				"perf_commit_latency",
				perfStat.Stats.CommitLatency.String(),
				"ms",
				const_label,
				"",
				var_label, "OSD Perf Commit Latency"},
			CephMetricStats{
				"perf_apply_latency",
				perfStat.Stats.ApplyLatency.String(),
				"ms",
				const_label,
				"",
				var_label, "OSD Perf Apply Latency"})

	}
	return returnMap, nil
}

func (cli *MetricCli) CollectOsddfMetrics() ([]CephMetricStats, error) {
	var returnMap []CephMetricStats
	returnMap = []CephMetricStats{}
	const_label := make(map[string]string)
	const_label["cluster"] = "ceph"
	cmd, err := json.Marshal(map[string]interface{}{
		"prefix": "osd df",
		"format": "json",
	})
	if err != nil {
		panic(err)
	}
	buf, _, err := cli.conn.MonCommand(cmd)
	if err != nil {
		log.Errorf("unable to collect data from ceph osd df")
	}
	osddf := &cephOSDDF{}
	if err := json.Unmarshal(buf, osddf); err != nil {
		log.Errorf("unmarshal failed")
	}
	for _, osd_df := range osddf.OSDNodes {
		var_label := make(map[string]string)
		var_label["osd"] = osd_df.Name.String()
		returnMap = append(returnMap,
			CephMetricStats{
				"osd_crush_weight",
				osd_df.CrushWeight.String(),
				"bytes", const_label,
				"",
				var_label, "OSD Crush Weight"})

	}
	returnMap = append(returnMap, CephMetricStats{
		"osd_total",
		osddf.Summary.TotalKB.String(),
		"bytes",
		const_label,
		"",
		nil, "OSD Total Storage Bytes"},
		CephMetricStats{
			"osd_total_used",
			osddf.Summary.TotalUsedKB.String(),
			"bytes",
			const_label,
			"",
			nil, "OSD Total Used Storage Bytes"},
		CephMetricStats{
			"total_avail",
			osddf.Summary.TotalAvailKB.String(),
			"bytes",
			const_label,
			"",
			nil, "OSD Total Available Storage Bytes"},
		CephMetricStats{
			"osd_average_utilization",
			osddf.Summary.AverageUtil.String(),
			"",
			const_label,
			"",
			nil, "OSD Average Utilization"})

	return returnMap, nil
}

func (cli *MetricCli) CollectOsddumpMetrics() ([]CephMetricStats, error) {
	var returnMap []CephMetricStats
	returnMap = []CephMetricStats{}
	const_label := make(map[string]string)
	const_label["cluster"] = "ceph"
	cmd, err := json.Marshal(map[string]interface{}{
		"prefix": "osd dump",
		"format": "json",
	})
	if err != nil {
		panic(err)
	}
	buf, _, err := cli.conn.MonCommand(cmd)
	if err != nil {
		log.Errorf("unable to collect data from ceph osd perf")
	}
	osd_dump := &cephOSDDump{}
	if err := json.Unmarshal(buf, osd_dump); err != nil {
		log.Errorf("unmarshal failed")
	}
	var_label := make(map[string]string)
	var_label["osd"] = fmt.Sprintf("osd.%s", osd_dump.OSDs[0].OSD.String())
	returnMap = append(returnMap,
		CephMetricStats{
			"osd_up",
			osd_dump.OSDs[0].Up.String(),
			"",
			const_label,
			"",
			var_label, ""},
		CephMetricStats{
			"osd_in",
			osd_dump.OSDs[0].In.String(),
			"",
			const_label,
			"",
			var_label, ""})
	return returnMap, nil
}

func (cli *MetricCli) CollectHealthMetrics() ([]CephMetricStats, error) {
	returnMap := []CephMetricStats{}
	constlabel := make(map[string]string)
	constlabel["cluster"] = "ceph"
	health_cmd, err := json.Marshal(map[string]interface{}{
		"prefix": "status",
		"format": "json",
	})
	if err != nil {
		log.Errorf("cmd failed with %s\n", err)
	}
	buff, _, err := cli.conn.MonCommand(health_cmd)
	if err != nil {
	}
	health_stats := &cephHealthStats{}
	if err := json.Unmarshal(buff, health_stats); err != nil {
		log.Fatalf("Unmarshal error: %v", err)
	}

	returnMap = append(returnMap, CephMetricStats{
		"client_io_write",
		health_stats.PGMap.WriteOpPerSec.String(),
		"", constlabel,
		"ops",
		nil, "Total client write I/O ops on the cluster measured per second"})

	returnMap = append(returnMap, CephMetricStats{
		"client_io_read",
		health_stats.PGMap.ReadBytePerSec.String(),
		"bytes", constlabel,
		"",
		nil, ""})

	returnMap = append(returnMap, CephMetricStats{
		"client_io_read",
		(health_stats.PGMap.ReadOpPerSec.String() + health_stats.PGMap.WriteOpPerSec.String()),
		"ops",
		constlabel,
		"",
		nil, "Total client read I/O ops on the cluster measured per second"})

	returnMap = append(returnMap, CephMetricStats{
		"client_io_write",
		health_stats.PGMap.WriteBytePerSec.String(),
		"bytes",
		constlabel,
		"",
		nil,
		"Rate of bytes being written by all clients per second"})

	returnMap = append(returnMap, CephMetricStats{
		"cache_evict_io",
		health_stats.PGMap.CacheEvictBytePerSec.String(),
		"bytes",
		constlabel,
		"",
		nil,
		"Rate of bytes being evicted from the cache pool per second"})

	returnMap = append(returnMap, CephMetricStats{
		"cache_promote_io",
		health_stats.PGMap.CachePromoteOpPerSec.String(),
		"",
		constlabel,
		"ops",
		nil,
		"Total cache promote operations measured per second"})

	returnMap = append(returnMap, CephMetricStats{
		"degraded_objects",
		health_stats.PGMap.DegradedObjects.String(),
		"", constlabel,
		"",
		nil,
		"No. of degraded objects across all PGs, includes replicas"})

	returnMap = append(returnMap, CephMetricStats{
		"misplaced_objects",
		health_stats.PGMap.MisplacedObjects.String(),
		"",
		constlabel,
		"",
		nil,
		"No. of misplaced objects across all PGs, includes replicas"})

	returnMap = append(returnMap, CephMetricStats{
		"osds",
		health_stats.OSDMap.OSDMap.NumOSDs.String(),
		"",
		constlabel,
		"",
		nil,
		"Count of total OSDs in the cluster"})

	returnMap = append(returnMap, CephMetricStats{
		"osds_up",
		health_stats.OSDMap.OSDMap.NumUpOSDs.String(),
		"",
		constlabel,
		"",
		nil,
		""})

	returnMap = append(returnMap, CephMetricStats{
		"osds_in",
		health_stats.OSDMap.OSDMap.NumInOSDs.String(),
		"",
		constlabel,
		"",
		nil,
		"Count of OSDs that are in IN state and available to serve requests"})

	returnMap = append(returnMap, CephMetricStats{
		"pgs_remapped",
		health_stats.OSDMap.OSDMap.NumRemappedPGs.String(),
		"", constlabel,
		"",
		nil,
		"No. of PGs that are remapped and incurring cluster-wide movement"})

	returnMap = append(returnMap, CephMetricStats{
		"total_pgs",
		health_stats.PGMap.NumPGs.String(),
		"",
		constlabel,
		"",
		nil,
		""})
	return returnMap, nil
}

func (cli *MetricCli) CollectMonitorsMetrics() ([]CephMetricStats, error) {
	var returnMap []CephMetricStats

	returnMap = []CephMetricStats{}
	const_label := make(map[string]string)
	const_label["cluster"] = "ceph"
	cmd, _ := json.Marshal(map[string]interface{}{
		"prefix": "status",
		"format": "json",
	})
	buf, _, err := cli.conn.MonCommand(cmd)
	if err != nil {

	}

	mon_stats := &cephMonitorStats{}
	if err := json.Unmarshal(buf, mon_stats); err != nil {
		log.Fatalf("unmarshal error: %v", err)
	}
	for _, healthService := range mon_stats.Health.Health.HealthServices {
		for _, monstat := range healthService.Mons {

			var_label := make(map[string]string)
			var_label["monitor"] = monstat.Name
			// TODO var name monstat.name

			kbTotal, _ := monstat.KBTotal.Float64()
			kbTotal_val := fmt.Sprintf("%f", kbTotal*1e3)
			returnMap = append(returnMap, CephMetricStats{
				"capacity",
				kbTotal_val,
				"bytes", const_label,
				"",
				var_label,
				"Total storage capacity of the monitor node"})

			kbUsed, _ := monstat.KBUsed.Float64()
			kbUsed_val := fmt.Sprintf("%f", kbUsed*1e3)
			returnMap = append(returnMap, CephMetricStats{
				"used",
				kbUsed_val,
				"bytes", const_label,
				"",
				var_label,
				"Storage of the monitor node that is currently allocated for use"})

			kbAvail, _ := monstat.KBAvail.Float64()
			kbAvail_val := fmt.Sprintf("%f", kbAvail*1e3)
			//m.AvailKBs.WithLabelValues(monstat.Name).Set(kbAvail * 1e3)
			returnMap = append(returnMap, CephMetricStats{
				"avail",
				kbAvail_val,
				"bytes", const_label,
				"",
				var_label,
				"Total unused storage capacity that the monitor node has left"})

			returnMap = append(returnMap, CephMetricStats{
				"avail_percent",
				monstat.AvailPercent.String(),
				"", const_label,
				"",
				var_label,
				"Percentage of total unused storage capacity that the monitor node has left"})

			returnMap = append(returnMap, CephMetricStats{
				"store_capacity",
				monstat.StoreStats.BytesTotal.String(),
				"bytes", const_label,
				"",
				var_label,
				"Total capacity of the FileStore backing the monitor daemon"})

			returnMap = append(returnMap, CephMetricStats{
				"store_sst",
				monstat.StoreStats.BytesSST.String(),
				"", const_label,
				"bytes",
				var_label,
				"Capacity of the FileStore used only for raw SSTs"})

			returnMap = append(returnMap, CephMetricStats{
				"store_log",
				monstat.StoreStats.BytesLog.String(),
				"bytes", const_label,
				"",
				var_label,
				"Capacity of the FileStore used only for logging"})

			returnMap = append(returnMap, CephMetricStats{
				"store_misc",
				monstat.StoreStats.BytesMisc.String(),
				"bytes", const_label,
				"",
				var_label,
				"Capacity of the FileStore used only for storing miscellaneous information"})
		}
	}

	cmd, _ = json.Marshal(map[string]interface{}{
		"prefix": "time-sync-status",
		"format": "json",
	})
	buf, _, err = cli.conn.MonCommand(cmd)
	if err != nil {
	}

	timeStats := &cephTimeSyncStatus{}
	if err := json.Unmarshal(buf, mon_stats); err != nil {
		log.Fatalf("unmarshal error: %v", err)
	}

	for monNode, tstat := range timeStats.TimeChecks {
		var_label := make(map[string]string)
		var_label["monitor"] = monNode
		returnMap = append(returnMap, CephMetricStats{
			"clock_skew_seconds",
			tstat.Skew.String(),
			"seconds",
			const_label,
			"",
			var_label,
			"Clock skew the monitor node is incurring"})

		returnMap = append(returnMap, CephMetricStats{
			"latency",
			tstat.Latency.String(),
			"seconds",
			const_label,
			"",
			var_label,
			"Latency the monitor node is incurring"})

		returnMap = append(returnMap, CephMetricStats{
			"quorum_count",
			fmt.Sprintf("%v", mon_stats.Quorum),
			"", const_label,
			"",
			var_label,
			"The total size of the monitor quorum"})

	}
	return returnMap, nil
}

func (cli *MetricCli) CollectMetrics(metricList []string, instanceID string) ([]CephMetricStats, error) {
	returnMap := []CephMetricStats{}

	//Collecting Pool Metrics
	pool_metric, _ := cli.CollectPoolMetrics()
	for i := range pool_metric {
		returnMap = append(returnMap, pool_metric[i])
	}
	cluster_metric, _ := cli.CollectClusterMetrics()
	for i := range cluster_metric {
		returnMap = append(returnMap, cluster_metric[i])
	}

	perf_metric, _ := cli.CollectPerfMetrics()
	for i := range perf_metric {
		returnMap = append(returnMap, perf_metric[i])
	}

	osd_df_metric, _ := cli.CollectOsddfMetrics()
	for i := range osd_df_metric {
		returnMap = append(returnMap, osd_df_metric[i])
	}

	osd_dump_metric, _ := cli.CollectOsddumpMetrics()
	for i := range osd_dump_metric {
		returnMap = append(returnMap, osd_dump_metric[i])
	}

	health_metrics, _ := cli.CollectHealthMetrics()
	for i := range health_metrics {
		returnMap = append(returnMap, health_metrics[i])
	}

	monitor_metrics, _ := cli.CollectMonitorsMetrics()
	for i := range monitor_metrics {
		returnMap = append(returnMap, monitor_metrics[i])
	}

	return returnMap, nil
}
