from packaging.version import parse as parse_version, InvalidVersion
import packaging.version
v_dep_str = "2.19.1"
v_start_str = "2.3.0"

try:
    dep_version_obj = parse_version(v_dep_str)
    start_ver = parse_version(v_start_str)

    print(f"Dependency Version Object: {dep_version_obj!r} (type: {type(dep_version_obj)})")
    print(f"Start Version Object: {start_ver!r} (type: {type(start_ver)})")
    print(f"Comparison: dep_version_obj < start_ver  =>  {dep_version_obj < start_ver}")

except InvalidVersion as e:
    print(f"Error parsing versions: {e}")
